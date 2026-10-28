package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)


const (
	// browserCookieName binds a login to the browser that started it (see
	// bindBrowser).
	browserCookieName = "sso_oidc_browser"
	browserCookieTTL  = 24 * time.Hour
)

// --- browser binding -------------------------------------------------------------

// Without a binding, a login started by an attacker (who then knows the
// request id) could be finished by a victim the attacker sent to the login
// URL. The browser that calls /authorize gets a random cookie; the request
// stores its hash; the login page and the callback only accept that
// browser. Keycloak does the same with its AUTH_SESSION_ID cookie.

type browserKey struct{}

func browserHashFrom(ctx context.Context) (string, bool) {
	h, ok := ctx.Value(browserKey{}).(string)
	return h, ok && h != ""
}

func (a *Adapter) bindBrowser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm, _ := realmFrom(r.Context())
		v := browserCookieValue(r)
		if v == "" {
			v = rand.Text()
		}
		// Set before the library writes its redirect: headers are still open.
		http.SetCookie(w, &http.Cookie{
			Name:     browserCookieName,
			Value:    v,
			Path:     "/r/" + realm.Name + "/oidc",
			MaxAge:   int(browserCookieTTL / time.Second),
			HttpOnly: true,
			Secure:   true,
			// Lax: the cookie must come along on the top-level navigation
			// from the application to /authorize (cross-site).
			SameSite: http.SameSiteLaxMode,
		})
		ctx := context.WithValue(r.Context(), browserKey{}, sha256Hex(v))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func browserCookieValue(r *http.Request) string {
	c, err := r.Cookie(browserCookieName)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 64 {
		return ""
	}
	return c.Value
}

func browserMatches(r *http.Request, ar *authRequest) bool {
	return browserHashMatches(r, ar.BrowserHash)
}

// browserHashMatches: the request comes from the browser whose binding
// cookie hashes to hash.
func browserHashMatches(r *http.Request, hash string) bool {
	v := browserCookieValue(r)
	return v != "" && hash != "" && subtle.ConstantTimeCompare([]byte(sha256Hex(v)), []byte(hash)) == 1
}

// checkBrowser guards the callback, which turns a completed login into a
// code: only the browser that started it may trigger that.
func (a *Adapter) checkBrowser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar, err := a.loadAuthRequest(r.Context(), r.URL.Query().Get("id"))
		if err != nil {
			a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
			return
		}
		if !browserMatches(r, ar) {
			a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
			return
		}
		next.ServeHTTP(w, r)
	})
}


func (a *Adapter) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	ar, err := a.loadAuthRequest(ctx, r.URL.Query().Get("id"))
	if err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	if !browserMatches(r, ar) {
		a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
		return
	}
	if r.URL.Query().Get("cancel") == "1" {
		a.authError(w, r, ar, oidc.ErrAccessDenied().WithDescription("the user cancelled the login"))
		return
	}
	if ar.Authenticated {
		a.redirectToCallback(w, r, ar)
		return
	}
	pc, err := a.core.LookupClient(ctx, realm.ID, protocolOIDC, ar.ClientID)
	if err != nil || pc.App.ID != ar.ClientRef {
		a.authError(w, r, ar, oidc.ErrAccessDenied().WithDescription("the application is not available"))
		return
	}

	sess := a.currentSession(r, realm)
	if sess != nil && a.mustPickAccount(ar, sess) {
		a.renderPicker(w, r, ar, pc, sess)
		return
	}
	if sess == nil || a.reauthRequired(ar, sess) {
		if ar.hasPrompt(oidc.PromptNone) {
			a.authError(w, r, ar, oidc.ErrLoginRequired())
			return
		}
		a.renderLogin(w, r, ar, pc, "login", nil)
		return
	}

	as, err := a.core.IssueIdentityAssertion(ctx, sess.ID, pc.App.ID, ar.Scopes)
	var mfaErr *core.MFARequiredError
	switch {
	case err == nil:
	case errors.As(err, &mfaErr):
		if ar.hasPrompt(oidc.PromptNone) {
			a.authError(w, r, ar, oidc.ErrInteractionRequired().WithDescription("a second factor is required"))
			return
		}
		mode := "stepup"
		if mfaErr.EnrollmentRequired {
			mode = "enroll"
		}
		a.renderLogin(w, r, ar, pc, mode, mfaErr.AllowedMethods)
		return
	case errors.Is(err, core.ErrSessionInvalid):
		a.renderLogin(w, r, ar, pc, "login", nil)
		return
	case errors.Is(err, core.ErrForbidden), errors.Is(err, core.ErrTimeoutActive):
		a.authError(w, r, ar, oidc.ErrAccessDenied().WithDescription("the user is not allowed to use this application"))
		return
	default:
		a.logger.ErrorContext(ctx, "oidc: identity assertion failed", "error", err, "client_id", ar.ClientID)
		a.authError(w, r, ar, oidc.ErrServerError())
		return
	}

	if !a.consentStep(w, r, ar, pc, sess, as) {
		return
	}

	ar.Authenticated = true
	ar.SessionID = sess.ID
	ar.Subject = as.Subject
	ar.AuthTime = as.AuthTime
	ar.AMR = as.AuthMethods
	if err := a.saveAuthRequest(ctx, ar); err != nil {
		a.logger.ErrorContext(ctx, "oidc: save authorization request", "error", err)
		a.authError(w, r, ar, oidc.ErrServerError())
		return
	}
	a.redirectToCallback(w, r, ar)
}

func (a *Adapter) currentSession(r *http.Request, realm Realm) *domain.Session {
	c, err := r.Cookie(a.cfg.SessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := a.core.ValidateSession(r.Context(), realm.ID, c.Value)
	if err != nil {
		return nil
	}
	return sess
}

// reauthRequired: prompt=login wants a login that happened during THIS
// request; max_age wants a recent one (OIDC Core, section 3.1.2.1).
// auth_time is the session creation. (prompt=select_account only asks to
// choose an account: see mustPickAccount.)
//
// A session created after the request started is always fine: the user has
// just typed their password for it. Without that rule, max_age=0 (which the
// library also sets for prompt=login) would ask for the password forever.
func (a *Adapter) reauthRequired(ar *authRequest, sess *domain.Session) bool {
	if !sess.CreatedAt.Before(ar.CreatedAt) {
		return false
	}
	if ar.hasPrompt(oidc.PromptLogin) {
		return true
	}
	return ar.MaxAge != nil && a.now().Sub(sess.CreatedAt) > time.Duration(*ar.MaxAge)*time.Second
}

// mustPickAccount: prompt=select_account shows "Pick an account" even with
// a valid session, until the user chose (the signed-in tile) or signed in
// during this request (a session newer than the request).
func (a *Adapter) mustPickAccount(ar *authRequest, sess *domain.Session) bool {
	return ar.hasPrompt(oidc.PromptSelectAccount) && !ar.AccountChosen && sess.CreatedAt.Before(ar.CreatedAt)
}

func (a *Adapter) redirectToCallback(w http.ResponseWriter, r *http.Request, ar *authRequest) {
	realm, _ := realmFrom(r.Context())
	http.Redirect(w, r, a.issuer(realm.Name)+"/oidc/authorize/callback?id="+url.QueryEscape(ar.ID), http.StatusFound)
}

// authError sends the user back to the application with an OAuth error
// (the redirect_uri was validated at /authorize), then forgets the request.
func (a *Adapter) authError(w http.ResponseWriter, r *http.Request, ar *authRequest, e *oidc.Error) {
	realm, _ := realmFrom(r.Context())
	r = r.WithContext(op.ContextWithIssuer(r.Context(), a.issuer(realm.Name)))
	if err := a.storage.DeleteAuthRequest(r.Context(), ar.ID); err != nil {
		a.logger.WarnContext(r.Context(), "oidc: delete authorization request", "error", err)
	}
	op.AuthRequestError(w, r, ar, e, a.provider)
}

func (a *Adapter) renderLogin(w http.ResponseWriter, r *http.Request, ar *authRequest, pc *core.ProtocolClient, mode string, allowed []domain.MfaMethodType) {
	page := a.loginPage(r, ar, pc, mode, allowed)
	if mode == "login" {
		realm, _ := realmFrom(r.Context())
		page.LoginHint, page.Accounts = a.signInChoices(r, realm, ar.LoginHint, pc.App.ID)
		if len(page.Accounts) > 0 {
			page.Mode = "pick"
		}
	}
	a.pages.RenderLogin(w, http.StatusOK, page)
}

// signInChoices: what the password form starts with.
//
//   - The browser has a session (prompt=login, max_age): its account,
//     pre-filled. The user signs in again as themselves.
//   - Else, with a login_hint: that hint, as before.
//   - Else: the accounts remembered on this device ("Pick an account"),
//     none of them signed in.
func (a *Adapter) signInChoices(r *http.Request, realm Realm, loginHint, clientRef string) (string, []loginui.Account) {
	ctx := r.Context()
	if sess := a.currentSession(r, realm); sess != nil {
		if loginHint == "" {
			if acc, err := a.core.SessionAccount(ctx, sess.ID); err == nil {
				loginHint = acc.Identifier
			}
		}
		return loginHint, nil
	}
	if loginHint != "" {
		return loginHint, nil
	}
	accounts, err := a.core.KnownAccounts(ctx, core.AccountQuery{RealmID: realm.ID, DeviceID: a.deviceID(r), ClientRef: clientRef})
	if err != nil {
		a.logger.WarnContext(ctx, "oidc: known accounts", "error", err)
		return "", nil
	}
	return "", loginui.AccountsFrom(accounts)
}

// renderPicker: prompt=select_account with a valid session. The signed-in
// account comes first; choosing it goes on with the session (a one-time
// token, like the consent page).
func (a *Adapter) renderPicker(w http.ResponseWriter, r *http.Request, ar *authRequest, pc *core.ProtocolClient, sess *domain.Session) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	accounts, err := a.core.KnownAccounts(ctx, core.AccountQuery{RealmID: realm.ID, DeviceID: a.deviceID(r), Current: sess, ClientRef: pc.App.ID})
	if err != nil {
		a.logger.ErrorContext(ctx, "oidc: known accounts", "error", err)
		a.authError(w, r, ar, oidc.ErrServerError())
		return
	}
	token := rand.Text()
	ar.PickTokenHash = sha256Hex(token)
	if err := a.saveAuthRequestKeepDeadline(ctx, ar); err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	page := a.loginPage(r, ar, pc, "pick", nil)
	page.Accounts = loginui.AccountsFrom(accounts)
	page.ContinueURL = "/r/" + realm.Name + "/oidc/login/continue"
	page.ContinueToken = token
	page.RequestID = ar.ID
	a.pages.RenderLogin(w, http.StatusOK, page)
}

type continueRequest struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// handleContinue: the signed-in tile of "Pick an account" was chosen. JSON
// (login.js), then the page reloads and the login goes on.
func (a *Adapter) handleContinue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	var req continueRequest
	if !isJSON(r) || json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req) != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ar, err := a.loadAuthRequest(ctx, req.ID)
	if err != nil || !browserMatches(r, ar) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if ar.PickTokenHash == "" || req.Token == "" ||
		subtle.ConstantTimeCompare([]byte(sha256Hex(req.Token)), []byte(ar.PickTokenHash)) != 1 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if a.currentSession(r, realm) == nil {
		writeJSONError(w, http.StatusConflict, "unauthenticated")
		return
	}
	ar.PickTokenHash, ar.AccountChosen = "", true
	if err := a.saveAuthRequestKeepDeadline(ctx, ar); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deviceID: the raw sso_device cookie ("" if absent). The core checks its
// format.
func (a *Adapter) deviceID(r *http.Request) string {
	c, err := r.Cookie(a.cfg.DeviceCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (a *Adapter) loginPage(r *http.Request, ar *authRequest, pc *core.ProtocolClient, mode string, allowed []domain.MfaMethodType) loginui.Login {
	realm, _ := realmFrom(r.Context())
	base := "/r/" + realm.Name
	methods := make([]string, 0, len(allowed))
	for _, m := range allowed {
		methods = append(methods, string(m))
	}
	page := loginui.Login{
		RealmDisplay: firstNonEmpty(realm.DisplayName, realm.Name),
		ClientName:   firstNonEmpty(pc.App.Name, pc.App.ClientID),
		ClientParam:  "client_id",
		ClientID:     pc.App.ClientID,
		Base:         base,
		Assets:       base + "/oidc/assets",
		Mode:         mode,
		Methods:      strings.Join(methods, ","),
		Passkeys:     a.cfg.PasskeysEnabled,
		LoginHint:    ar.LoginHint,
		CancelURL:    base + "/oidc/login?id=" + url.QueryEscape(ar.ID) + "&cancel=1",
	}
	if a.cfg.DevPages {
		page.EnrollURL = base + "/dev/mfa"
	}
	if a.cfg.PasswordReset {
		page.ForgotPasswordURL = base + "/auth/forgot-password"
	}
	page.RememberMe, page.RememberMeDays = loginui.RememberMeOffer(a.core.SessionOptions(r.Context(), realm.ID))
	return page
}

// --- other pages -------------------------------------------------------------------

type message = loginui.Message

var (
	msgExpired = message{Title: "This sign-in link has expired",
		Text: "Go back to the application and start the sign-in again."}
	msgOtherBrowser = message{Title: "Sign-in started in another browser",
		Text: "For your security, a sign-in must be finished in the browser that started it. Go back to the application and start again here."}
	msgLoggedOut = message{Title: "You are signed out", Text: "You can close this window."}

	msgLogoutExpired = message{Title: "This sign-out has expired",
		Text: "Nothing was changed. Go back to the application and sign out again if you still want to."}
	msgLogoutFailed = message{Title: "Sign-out failed",
		Text: "Your session could not be ended. Try again in a moment."}
)

func (a *Adapter) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	a.renderMessage(w, r, http.StatusOK, msgLoggedOut)
}

func (a *Adapter) renderMessage(w http.ResponseWriter, r *http.Request, status int, m message) {
	realm, _ := realmFrom(r.Context())
	a.pages.RenderMessage(w, status, m, "/r/"+realm.Name+"/oidc/assets")
}

func handleAsset(w http.ResponseWriter, r *http.Request) {
	loginui.Asset(w, r, chi.URLParam(r, "file"))
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
