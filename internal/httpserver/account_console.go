package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/adapters/accountui"
	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

// Account console (Step 14c, spec-panel-user.md): the pages where a user
// manages their own account, at /r/{realm}/account, on the public server
// next to the sign-in pages. The console reads the SSO session cookie of
// its realm directly: no OIDC client is involved.
//
//	no session        the sign-in page (loginui), which reloads the console
//	                  once signed in
//	sensitive change  "Confirm it's you" first (accountStepUp): a second
//	                  factor again, or a new sign-in for an account without
//	                  one
//	every POST        two CSRF checks: http.CrossOriginProtection (the
//	                  browser's Sec-Fetch-Site / Origin headers) AND a token
//	                  derived from the session in a hidden field
//
// Every form works without JavaScript (POST, then 303 to the page with a
// one-time notice). With htmx (HX-Request: true), the same handlers answer
// with the part of the page that changed.

const (
	accountFlashCookie = "sso_account_flash"
	csrfField          = "csrf"
	maxAccountFormSize = 16 << 10

	// The organizations this browser signed in to (account console menu).
	realmsCookieName = "sso_realms"
	realmsCookiePath = "/r"
	maxRememberedOrg = 10

	routeAccountPassword   = "account.password"
	accountPasswordPerUser = 5
)

// WithAccountConsole mounts the account console. It needs the MFA service
// (WithMFA): without it the console is not mounted.
func WithAccountConsole(acc *service.AccountService) Option {
	return func(s *Server) { s.account = acc }
}

// acct is what every console handler works with: the realm, the session of
// the browser and its user.
type acct struct {
	realm *domain.Realm
	sess  *domain.Session
	user  *domain.User
	csrf  string
}

type acctKey struct{}

func acctFrom(r *http.Request) *acct {
	a, _ := r.Context().Value(acctKey{}).(*acct)
	return a
}

func accountBase(realmName string) string { return "/r/" + realmName + "/account" }

func (s *Server) mountAccount(r chi.Router) {
	pages, err := accountui.New(nil)
	if err != nil {
		panic("httpserver: account pages: " + err.Error()) // embedded templates: a bug, not a runtime error
	}
	login, err := loginui.New(nil)
	if err != nil {
		panic("httpserver: login pages: " + err.Error())
	}
	s.accountPages, s.loginPages = pages, login

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.accountMessage(w, r, http.StatusForbidden, "Request refused",
			"This request did not come from this site. Go back to your account and try again.", "refused")
	}))

	r.Route("/account", func(r chi.Router) {
		r.Get("/assets/{file}", s.handleAccountAsset)
		r.Group(func(r chi.Router) {
			r.Use(cop.Handler, s.accountSession)

			r.Get("/", s.handleAccountProfile)
			r.Post("/profile", s.handleAccountProfileSave)
			r.Post("/signout", s.handleAccountSignOut)

			r.Get("/security", s.handleAccountSecurity)
			r.Get("/security/password", s.handleAccountPassword)
			r.Post("/security/password", s.handleAccountPasswordSave)
			r.Get("/security/totp", s.handleAccountTOTP)
			r.Post("/security/totp", s.handleAccountTOTPStart)
			r.Post("/security/totp/{methodID}/confirm", s.handleAccountTOTPConfirm)
			r.Get("/security/passkey", s.handleAccountPasskey)
			r.Get("/security/factors/{methodID}/remove", s.handleAccountRemoveFactor)
			r.Post("/security/factors/{methodID}/remove", s.handleAccountRemoveFactorConfirm)
			r.Get("/security/backup-codes", s.handleAccountBackupCodes)
			r.Post("/security/backup-codes", s.handleAccountBackupCodesNew)
			r.Post("/security/devices/{deviceID}/revoke", s.handleAccountRevokeDevice)
			r.Post("/security/devices/revoke-all", s.handleAccountRevokeDevices)

			r.Get("/sessions", s.handleAccountSessions)
			r.Post("/sessions/{sessionID}/revoke", s.handleAccountRevokeSession)
			r.Post("/sessions/revoke-others", s.handleAccountRevokeOtherSessions)

			r.Get("/apps", s.handleAccountApps)
			r.Post("/apps/{clientRef}/revoke", s.handleAccountRevokeApp)

			r.Get("/history", s.handleAccountHistory)
		})
	})
}

// handleAccountAsset serves the console's files, and the sign-in page's
// (login.css, login.js) for the sign-in shown by the console; loginui.Asset
// also serves the design system (omsso.css and its fonts).
func (s *Server) handleAccountAsset(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "file")
	if accountui.HasAsset(name) {
		accountui.Asset(w, r, name)
		return
	}
	loginui.Asset(w, r, name)
}

// accountSession finds the session of the browser. Without one, a GET
// shows the sign-in page and anything else goes back to the console. A
// POST must carry the CSRF token of the session.
func (s *Server) accountSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		realm := realmFromContext(r)
		raw := sessionTokenFromRequest(r)
		var sess *domain.Session
		if raw != "" {
			se, err := s.sessions.Validate(ctx, realm.ID, raw)
			switch {
			case err == nil:
				sess = se
			case errors.Is(err, service.ErrSessionInvalid):
				clearSessionCookie(w, realm.Name)
			default:
				s.accountFailure(w, r, err)
				return
			}
		}
		var user *domain.User
		if sess != nil {
			u, err := s.mfa.User(ctx, sess.UserID)
			if err != nil || u.Status != domain.UserActive || u.RealmID != realm.ID {
				sess = nil
			} else {
				user = u
			}
		}
		if sess == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				s.accountSignIn(w, r, realm)
			} else {
				s.accountRedirect(w, r, accountBase(realm.Name))
			}
			return
		}

		a := &acct{realm: realm, sess: sess, user: user, csrf: accountCSRF(raw)}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxAccountFormSize)
			if err := r.ParseForm(); err != nil ||
				subtle.ConstantTimeCompare([]byte(r.PostForm.Get(csrfField)), []byte(a.csrf)) != 1 {
				s.accountMessage(w, r, http.StatusForbidden, "Request refused",
					"This form has expired. Go back to your account and try again.", "refused")
				return
			}
		}
		ctx = context.WithValue(ctx, acctKey{}, a)
		ctx = context.WithValue(ctx, sessionContextKey{}, sess)
		ctx = audit.WithActor(ctx, audit.Actor{UserID: user.ID, RealmID: realm.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// accountCSRF derives the anti-CSRF token of a session: another site can
// neither read the session cookie (HttpOnly) nor this page, so it cannot
// know the token. A new session (sign-in again) gets a new token.
func accountCSRF(rawSessionToken string) string {
	sum := sha256.Sum256([]byte("oh-my-sso/account-csrf/v1|" + service.HashSessionToken(rawSessionToken)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// accountSignIn shows the sign-in page in place of the console; once
// signed in, the page reloads and the console shows.
func (s *Server) accountSignIn(w http.ResponseWriter, r *http.Request, realm *domain.Realm) {
	page := s.loginPage(realm, "login")
	page.Subtitle = "to manage your account"
	page.RememberMe, page.RememberMeDays = s.rememberMeOffer(r.Context(), realm.ID)
	s.loginPages.RenderLogin(w, http.StatusOK, page)
}

func (s *Server) loginPage(realm *domain.Realm, mode string) loginui.Login {
	base := "/r/" + realm.Name
	page := loginui.Login{
		RealmDisplay: realmDisplay(realm.DisplayName, realm.Name),
		ClientParam:  "client_id",
		Base:         base,
		Assets:       accountBase(realm.Name) + "/assets",
		Mode:         mode,
		Passkeys:     s.mfa.PasskeysEnabled(),
	}
	if s.forgotPassword {
		page.ForgotPasswordURL = base + "/auth/forgot-password"
	}
	return page
}

func (s *Server) rememberMeOffer(ctx context.Context, realmID string) (bool, int) {
	allowed, lifetime := s.sessions.RememberMeOption(ctx, realmID)
	days := int(lifetime.Hours() / 24)
	return allowed && days > 0, days
}

// accountStepUp checks that the user proved who they are recently enough
// to change how they sign in (service.StepUpAccountSecurity: a second
// factor within the realm's step-up window, or a recent sign-in for an
// account without one). Otherwise a GET shows "Confirm it's you" at the
// same address (it reloads into the page once done) and anything else is
// sent to gate, the GET page of the same change. ignoreRecentLogin: the
// change itself asks for the password (changing it), which proves as much
// as signing in again.
func (s *Server) accountStepUp(w http.ResponseWriter, r *http.Request, a *acct, gate string, ignoreRecentLogin bool) bool {
	err := s.mfa.CheckStepUp(r.Context(), a.sess, service.StepUpAccountSecurity)
	var su *service.StepUpRequiredError
	switch {
	case err == nil:
		return true
	case errors.As(err, &su):
		if ignoreRecentLogin && su.Reason == service.StepUpNeedRecentLogin {
			return true
		}
		if r.Method != http.MethodGet {
			setFlash(w, a.realm.Name, "confirm_first", 0)
			s.accountRedirect(w, r, gate)
			return false
		}
		mode := "stepup"
		page := s.loginPage(a.realm, mode)
		page.Notice = "For your security, confirm it's you to continue."
		if su.Reason == service.StepUpNeedRecentLogin {
			page = s.loginPage(a.realm, "login")
			page.LoginHint = a.user.Username
			page.Notice = "For your security, enter your password again to continue."
		}
		page.Subtitle = "to change how you sign in"
		page.CancelURL, page.CancelText = accountBase(a.realm.Name)+"/security", "Back to your account"
		s.loginPages.RenderLogin(w, http.StatusOK, page)
		return false
	default:
		s.accountFailure(w, r, err)
		return false
	}
}

// --- rendering ---------------------------------------------------------------

func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// accountRedirect: 303 for a form, HX-Redirect (a full navigation) for htmx.
func (s *Server) accountRedirect(w http.ResponseWriter, r *http.Request, to string) {
	if isHTMX(r) {
		accountui.SecurityHeaders(w.Header())
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// accountMessage answers with a short page (a refused request, an error).
// htmx does not swap error answers into the page: for htmx, the page
// reloads instead (HX-Refresh) and shows flash as its notice.
func (s *Server) accountMessage(w http.ResponseWriter, r *http.Request, status int, title, text, flash string) {
	realm := realmFromContext(r)
	if isHTMX(r) && realm != nil {
		setFlash(w, realm.Name, flash, 0)
		accountui.SecurityHeaders(w.Header())
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	assets := ""
	if realm != nil {
		assets = accountBase(realm.Name) + "/assets"
	}
	s.loginPages.RenderMessage(w, status, loginui.Message{Title: title, Text: text}, assets)
}

func (s *Server) accountFailure(w http.ResponseWriter, r *http.Request, err error) {
	slog.Default().ErrorContext(r.Context(), "account console", "path", r.URL.Path, "error", err)
	s.accountMessage(w, r, http.StatusInternalServerError, "Something went wrong",
		"The page could not be shown. Try again in a moment.", "failed")
}

// accountLayout fills what every page shows. It reads (and clears) the
// one-time notice of the previous action.
func (s *Server) accountLayout(w http.ResponseWriter, r *http.Request, a *acct, active, title string) accountui.Layout {
	base := accountBase(a.realm.Name)
	l := accountui.Layout{
		Title:  title,
		Org:    accountui.Org{Name: a.realm.Name, Display: realmDisplay(a.realm.DisplayName, a.realm.Name), URL: base, Current: true},
		User:   accountui.Person{Name: personName(a.user), Email: a.user.Email, Initials: initialsOf(personName(a.user))},
		Active: active,
		Base:   base,
		Assets: base + "/assets",
		CSRF:   a.csrf,
		Theme:  accountui.ThemeFrom(r),
	}
	l.Orgs = s.accountOrgs(r, a.realm)
	l.Notice, l.Error = s.takeFlash(w, r, a)
	if st, err := s.mfa.Status(r.Context(), a.sess, nil); err == nil {
		l.MFARequired = st.EnrollmentRequired
	}
	return l
}

// personName: the profile's name, else first + last name, else the username.
func personName(u *domain.User) string {
	if n, ok := u.Profile["name"].(string); ok && strings.TrimSpace(n) != "" {
		return strings.TrimSpace(n)
	}
	given, _ := u.Profile["given_name"].(string)
	family, _ := u.Profile["family_name"].(string)
	if n := strings.TrimSpace(given + " " + family); n != "" {
		return n
	}
	return u.Username
}

// initialsOf: first letter of the first two words ("Dana Scully" -> "DS").
func initialsOf(name string) string {
	var out []rune
	for _, w := range strings.Fields(name) {
		for _, r := range w {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				out = append(out, unicode.ToUpper(r))
				break
			}
		}
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

// --- one-time notices ---------------------------------------------------------

// The notice of the last action travels in a short-lived cookie as a key
// (never as text: a forged cookie can only pick one of these sentences).
var flashText = map[string]string{
	"profile_saved":    "Your name was saved.",
	"password_changed": "Your password was changed. Your other sessions were signed out.",
	"totp_added":       "Authenticator app added.",
	"passkey_added":    "Passkey or security key added.",
	"factor_removed":   "Removed.",
	"session_revoked":  "That session was signed out.",
	"sessions_revoked": "Your other sessions were signed out.",
	"device_revoked":   "That device will ask for the second step again.",
	"devices_revoked":  "Every device will ask for the second step again.",
	"app_revoked":      "Access removed.",
	"confirm_first":    "For your security, confirm it's you, then try again.",
	"not_found":        "That item no longer exists.",
	"enroll_expired":   "This setup expired. Start again.",
	"refused":          "This form had expired: nothing was changed. Try again.",
	"failed":           "Something went wrong: nothing was changed. Try again in a moment.",
}

// flashValue: a key, with a count for the sentences that show one.
func flashValue(key string, n int) string {
	if n > 0 {
		return key + "." + strconv.Itoa(n)
	}
	return key
}

func setFlash(w http.ResponseWriter, realmName, key string, n int) {
	http.SetCookie(w, &http.Cookie{
		Name: accountFlashCookie, Value: flashValue(key, n), Path: accountBase(realmName), MaxAge: 60,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// takeFlash returns the notice (or error) of the previous action, and
// clears it. A "done" query parameter (set by account.js after a passkey
// is added) works the same way.
func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request, a *acct) (notice, problem string) {
	key := ""
	if c, err := r.Cookie(accountFlashCookie); err == nil {
		key = c.Value
		http.SetCookie(w, &http.Cookie{
			Name: accountFlashCookie, Value: "", Path: accountBase(a.realm.Name), MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	if key == "" && r.URL.Query().Get("done") == "passkey" {
		key = "passkey_added"
	}
	return flashParts(key)
}

// flashParts turns a notice key ("sessions_revoked.3") into its sentence:
// a confirmation, or a problem.
func flashParts(value string) (notice, problem string) {
	key, count, _ := strings.Cut(value, ".")
	text, ok := flashText[key]
	if !ok {
		return "", ""
	}
	if key == "password_changed" || key == "sessions_revoked" {
		if n, err := strconv.Atoi(count); err == nil && n > 0 {
			text = strings.TrimSuffix(text, ".") + " (" + strconv.Itoa(n) + ")."
		}
	}
	switch key {
	case "confirm_first", "not_found", "enroll_expired", "refused", "failed":
		return "", text
	}
	return text, ""
}

// setNotice shows a notice in an htmx answer (no cookie: same request).
func setNotice(l *accountui.Layout, value string) {
	l.Notice, l.Error = flashParts(value)
}

// --- organizations of this browser ------------------------------------------

// Each realm has its own session cookie (Path=/r/<realm>): the console of
// one realm cannot see another realm's session. To list "the organizations
// you use on this browser", a sign-in adds its realm name to sso_realms
// (Path=/r, HttpOnly). It holds realm names only: no account, no session.
// Nothing links accounts across realms on the server (realms are separate
// tenants); the list is a convenience of this browser.

// realmsFromRequest: the remembered realm names, most recent first, only
// well-formed names.
func realmsFromRequest(r *http.Request) []string {
	c, err := r.Cookie(realmsCookieName)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range strings.Split(c.Value, ".") {
		if validRealmName(n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
		if len(out) == maxRememberedOrg {
			break
		}
	}
	return out
}

// validRealmName: the shape of realm names (a-z, 0-9, "-", 2 to 63).
func validRealmName(n string) bool {
	if len(n) < 2 || len(n) > 63 {
		return false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func writeRealms(w http.ResponseWriter, names []string) {
	if len(names) == 0 {
		http.SetCookie(w, &http.Cookie{Name: realmsCookieName, Value: "", Path: realmsCookiePath, MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: realmsCookieName, Value: strings.Join(names, "."), Path: realmsCookiePath,
		MaxAge: int(deviceCookieMaxAge.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// rememberRealm puts a realm first in the list (a sign-in there).
func rememberRealm(w http.ResponseWriter, r *http.Request, realmName string) {
	names := []string{realmName}
	for _, n := range realmsFromRequest(r) {
		if n != realmName && len(names) < maxRememberedOrg {
			names = append(names, n)
		}
	}
	writeRealms(w, names)
}

// forgetRealm takes a realm out of the list (signed out there).
func forgetRealm(w http.ResponseWriter, r *http.Request, realmName string) {
	names := slices.DeleteFunc(realmsFromRequest(r), func(n string) bool { return n == realmName })
	writeRealms(w, names)
}

// accountOrgs: the current realm and the other active realms of the list.
func (s *Server) accountOrgs(r *http.Request, current *domain.Realm) []accountui.Org {
	out := []accountui.Org{{Name: current.Name, Display: realmDisplay(current.DisplayName, current.Name),
		URL: accountBase(current.Name), Current: true}}
	for _, name := range realmsFromRequest(r) {
		if name == current.Name {
			continue
		}
		realm, err := s.realms.GetByName(r.Context(), name)
		if err != nil || realm.Status != domain.RealmActive {
			continue
		}
		out = append(out, accountui.Org{Name: realm.Name, Display: realmDisplay(realm.DisplayName, realm.Name), URL: accountBase(realm.Name)})
	}
	return out
}
