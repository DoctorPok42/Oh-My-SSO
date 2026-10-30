package httpserver

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/adapters/accountui"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/ratelimit"
)

// The pages of the account console (see account_console.go for the
// session, CSRF and "Confirm it's you" rules they all follow).

const historyPageSize = 25

func (s *Server) accountEvent(r *http.Request) service.AccountEvent {
	return service.AccountEvent{IPAddress: clientIP(r), UserAgent: r.UserAgent()}
}

// --- profile -------------------------------------------------------------------

func (s *Server) profilePage(w http.ResponseWriter, r *http.Request, a *acct) accountui.ProfilePage {
	given, _ := a.user.Profile["given_name"].(string)
	family, _ := a.user.Profile["family_name"].(string)
	verified, _ := a.user.Profile["email_verified"].(bool)
	return accountui.ProfilePage{
		Layout:   s.accountLayout(w, r, a, "profile", "Profile"),
		Username: a.user.Username, Email: a.user.Email, EmailVerified: verified,
		GivenName: given, FamilyName: family,
	}
}

func (s *Server) handleAccountProfile(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageProfile, s.profilePage(w, r, a))
}

func (s *Server) handleAccountProfileSave(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	in := service.NameInput{GivenName: r.PostForm.Get("given_name"), FamilyName: r.PostForm.Get("family_name")}
	u, err := s.account.UpdateName(r.Context(), a.user, in, s.accountEvent(r))
	switch {
	case errors.Is(err, service.ErrInvalidName):
		page := s.profilePage(w, r, a)
		page.GivenName, page.FamilyName = in.GivenName, in.FamilyName
		page.FormError = "Each name can be at most 100 characters long."
		if isHTMX(r) {
			s.accountPages.RenderPartial(w, accountui.PageProfile, "profile-form", page)
			return
		}
		s.accountPages.RenderPage(w, http.StatusUnprocessableEntity, accountui.PageProfile, page)
		return
	case err != nil:
		s.accountFailure(w, r, err)
		return
	}
	if isHTMX(r) {
		a.user = u
		page := s.profilePage(w, r, a)
		page.Saved = true
		s.accountPages.RenderPartial(w, accountui.PageProfile, "profile-form", page)
		return
	}
	setFlash(w, a.realm.Name, "profile_saved", 0)
	s.accountRedirect(w, r, accountBase(a.realm.Name))
}

func (s *Server) handleAccountSignOut(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if err := s.sessions.Logout(r.Context(), sessionTokenFromRequest(r), service.LogoutEvent{
		Via: domain.LogoutViaAccount, IPAddress: clientIP(r), UserAgent: r.UserAgent(),
	}); err != nil {
		s.accountFailure(w, r, err)
		return
	}
	clearSessionCookie(w, a.realm.Name)
	forgetRealm(w, r, a.realm.Name)
	s.accountRedirect(w, r, accountBase(a.realm.Name))
}

// --- security ------------------------------------------------------------------

var factorLabels = map[domain.MfaMethodType]string{
	domain.MfaMethodTOTP:     "Authenticator app",
	domain.MfaMethodPasskey:  "Passkey",
	domain.MfaMethodWebAuthn: "Security key",
}

func factorView(m *domain.MfaMethod) accountui.Factor {
	kind := string(m.Type)
	if m.Type == domain.MfaMethodWebAuthn {
		kind = "security_key"
	}
	label := factorLabels[m.Type]
	if label == "" {
		label = "Second step"
	}
	f := accountui.Factor{ID: m.ID, Kind: kind, KindLabel: label, Name: m.Name, CreatedAt: m.CreatedAt}
	if !m.LastUsedAt.IsZero() {
		t := m.LastUsedAt
		f.LastUsed = &t
	}
	return f
}

func (s *Server) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	ctx := r.Context()
	factors, err := s.mfa.ListFactors(ctx, a.user.ID)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	page := accountui.SecurityPage{
		Layout:          s.accountLayout(w, r, a, "security", "Security"),
		HasPassword:     a.user.PasswordHash != "",
		PasskeysEnabled: s.mfa.PasskeysEnabled(),
		BackupRemaining: factors.BackupCodes.Remaining,
		BackupTotal:     factors.BackupCodes.Total,
	}
	for _, m := range factors.Methods {
		page.Factors = append(page.Factors, factorView(m))
	}
	if page.TrustedDevices, err = s.trustedDeviceViews(r, a); err != nil {
		s.accountFailure(w, r, err)
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageSecurity, page)
}

func (s *Server) trustedDeviceViews(r *http.Request, a *acct) ([]accountui.TrustedDevice, error) {
	devices, err := s.account.TrustedDevices(r.Context(), a.user)
	if err != nil {
		return nil, err
	}
	here := service.DeviceFingerprint(deviceIDFromRequest(r))
	out := make([]accountui.TrustedDevice, 0, len(devices))
	for _, d := range devices {
		v := accountui.TrustedDevice{ID: d.ID, Device: deviceName(d.UserAgent), Current: here != "" && d.DeviceHash == here,
			CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt}
		if !d.LastUsedAt.IsZero() {
			t := d.LastUsedAt
			v.LastUsed = &t
		}
		out = append(out, v)
	}
	return out, nil
}

func deviceName(ua string) string {
	if d := notify.DescribeUserAgent(ua); d != "" {
		return d
	}
	return "Unknown device"
}

// devicesAnswer: after a change to the trusted devices, the new list
// (htmx) or the Security page.
func (s *Server) devicesAnswer(w http.ResponseWriter, r *http.Request, a *acct, flash string, n int) {
	if !isHTMX(r) {
		setFlash(w, a.realm.Name, flash, n)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
		return
	}
	page := accountui.SecurityPage{Layout: s.accountLayout(w, r, a, "security", "Security")}
	setNotice(&page.Layout, flashValue(flash, n))
	var err error
	if page.TrustedDevices, err = s.trustedDeviceViews(r, a); err != nil {
		s.accountFailure(w, r, err)
		return
	}
	s.renderWithNotice(w, r, accountui.PageSecurity, "devices", page, page.Layout)
}

// renderWithNotice writes an htmx answer: the changed block, plus the
// notice area (out of band).
func (s *Server) renderWithNotice(w http.ResponseWriter, r *http.Request, page, block string, data any, l accountui.Layout) {
	rec := &bufferedWriter{header: http.Header{}}
	s.accountPages.RenderPartial(rec, page, block, data)
	s.accountPages.RenderPartial(rec, page, "notice-oob", l)
	if rec.failed {
		s.accountFailure(w, r, errors.New("render "+page+"/"+block))
		return
	}
	accountui.SecurityHeaders(w.Header())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rec.body.Bytes())
}

func (s *Server) handleAccountRevokeDevice(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	err := s.account.RevokeTrustedDevice(r.Context(), a.user, chi.URLParam(r, "deviceID"), s.accountEvent(r))
	switch {
	case errors.Is(err, service.ErrTrustedDeviceNotFound):
		s.devicesAnswer(w, r, a, "not_found", 0)
	case err != nil:
		s.accountFailure(w, r, err)
	default:
		s.devicesAnswer(w, r, a, "device_revoked", 0)
	}
}

func (s *Server) handleAccountRevokeDevices(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if _, err := s.account.RevokeTrustedDevices(r.Context(), a.user, s.accountEvent(r)); err != nil {
		s.accountFailure(w, r, err)
		return
	}
	s.devicesAnswer(w, r, a, "devices_revoked", 0)
}

// --- password --------------------------------------------------------------

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request, a *acct) accountui.PasswordPage {
	return accountui.PasswordPage{
		Layout:    s.accountLayout(w, r, a, "security", "Change your password"),
		Username:  a.user.Username,
		MinLength: s.account.MinPasswordLength(r.Context(), a.realm.ID),
		MaxLength: service.MaxPasswordLength,
	}
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if a.user.PasswordHash == "" {
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
		return
	}
	if !s.accountStepUp(w, r, a, r.URL.Path, true) {
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PagePassword, s.passwordPage(w, r, a))
}

func (s *Server) handleAccountPasswordSave(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	ctx := r.Context()
	if !s.accountStepUp(w, r, a, r.URL.Path, true) {
		return
	}
	fail := func(status int, msg string) {
		page := s.passwordPage(w, r, a)
		page.FormError = msg
		s.accountPages.RenderPage(w, status, accountui.PagePassword, page)
	}
	ok, err := s.rateLimiter.Allow(ctx, ratelimit.Key(routeAccountPassword, a.realm.ID, "user", a.user.ID),
		accountPasswordPerUser, loginRateLimitWindow)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	if !ok {
		fail(http.StatusTooManyRequests, "Too many attempts. Wait a few minutes, then try again.")
		return
	}
	current, next, confirm := r.PostForm.Get("current"), r.PostForm.Get("new"), r.PostForm.Get("confirm")
	if next != confirm {
		fail(http.StatusUnprocessableEntity, "The two new passwords are not the same.")
		return
	}
	if len(current) > maxPasswordLen || len(next) > maxPasswordLen {
		fail(http.StatusUnprocessableEntity, "This password is too long.")
		return
	}
	res, err := s.account.ChangePassword(ctx, service.ChangePasswordInput{
		User: a.user, SessionID: a.sess.ID, Current: current, New: next, Event: s.accountEvent(r),
	})
	var policy *service.PasswordPolicyError
	switch {
	case errors.Is(err, service.ErrWrongPassword):
		fail(http.StatusUnprocessableEntity, "Your current password is not right.")
	case errors.Is(err, service.ErrPasswordUnchanged):
		fail(http.StatusUnprocessableEntity, "The new password must be different from the current one.")
	case errors.As(err, &policy):
		switch {
		case errors.Is(err, service.ErrPasswordTooShort):
			fail(http.StatusUnprocessableEntity, "The new password must be at least "+strconv.Itoa(policy.MinLength)+" characters long.")
		case errors.Is(err, service.ErrPasswordTooLong):
			fail(http.StatusUnprocessableEntity, "The new password must be at most "+strconv.Itoa(policy.MaxLength)+" characters long.")
		case errors.Is(err, service.ErrPasswordMatchesIdentity):
			fail(http.StatusUnprocessableEntity, "The new password must not be your username or e-mail address.")
		default:
			fail(http.StatusUnprocessableEntity, "This password cannot be used.")
		}
	case errors.Is(err, service.ErrNoPassword):
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
	case err != nil:
		s.accountFailure(w, r, err)
	default:
		setFlash(w, a.realm.Name, "password_changed", res.SessionsEnded)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
	}
}

// --- authenticator app (TOTP) ------------------------------------------------

func (s *Server) handleAccountTOTP(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.accountStepUp(w, r, a, r.URL.Path, false) {
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageTOTP, accountui.TOTPPage{
		Layout: s.accountLayout(w, r, a, "security", "Add an authenticator app"), Step: "name",
	})
}

func (s *Server) handleAccountTOTPStart(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.accountStepUp(w, r, a, r.URL.Path, false) {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	enr, err := s.mfa.StartTOTPEnrollment(r.Context(), a.user, name)
	if err != nil {
		if errors.Is(err, service.ErrInvalidMFAPolicy) {
			s.accountPages.RenderPage(w, http.StatusUnprocessableEntity, accountui.PageTOTP, accountui.TOTPPage{
				Layout: s.accountLayout(w, r, a, "security", "Add an authenticator app"), Step: "name", Name: name,
				FormError: "The name is at most 100 characters.",
			})
			return
		}
		s.accountFailure(w, r, err)
		return
	}
	page := accountui.TOTPPage{
		Layout: s.accountLayout(w, r, a, "security", "Add an authenticator app"),
		Step:   "scan", Name: name, MethodID: enr.MethodID, Secret: groupKey(enr.Secret), ExpiresAt: enr.ExpiresAt,
	}
	// The QR code is a PNG made by the server (never user input): safe to
	// use as an image URL. Anything else is not shown.
	if strings.HasPrefix(enr.QRCodePNG, "data:image/png;base64,") {
		page.QR = template.URL(enr.QRCodePNG) // #nosec G203 -- server-generated data URI
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageTOTP, page)
}

// groupKey: "JBSWY3DPEHPK3PXP" -> "JBSW Y3DP EHPK 3PXP", easier to type.
func groupKey(k string) string {
	var b strings.Builder
	for i, r := range k {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Server) handleAccountTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	methodID := chi.URLParam(r, "methodID")
	code := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, r.PostForm.Get("code"))
	res, err := s.mfa.ConfirmTOTPEnrollment(r.Context(), a.user, a.sess, methodID, code)
	retry := func(msg string) {
		page := accountui.TOTPPage{
			Layout: s.accountLayout(w, r, a, "security", "Add an authenticator app"),
			Step:   "scan", MethodID: methodID, FormError: msg,
		}
		if isHTMX(r) {
			s.accountPages.RenderPartial(w, accountui.PageTOTP, "totp-code-area", page)
			return
		}
		s.accountPages.RenderPage(w, http.StatusUnprocessableEntity, accountui.PageTOTP, page)
	}
	var codeErr *service.MFACodeError
	switch {
	case errors.As(err, &codeErr), errors.Is(err, service.ErrInvalidMFACode):
		retry("This code is not right. Check the time of your phone, then enter the new code.")
		return
	case errors.Is(err, service.ErrMFARateLimited):
		retry("Too many attempts. Wait a few minutes, then try again.")
		return
	case errors.Is(err, service.ErrMFAEnrollmentExpired), errors.Is(err, service.ErrMFAMethodNotFound):
		setFlash(w, a.realm.Name, "enroll_expired", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security/totp")
		return
	case err != nil:
		s.accountFailure(w, r, err)
		return
	}
	if len(res.BackupCodes) == 0 {
		setFlash(w, a.realm.Name, "totp_added", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
		return
	}
	// The first second factor: its backup codes, shown once, right now.
	page := accountui.BackupCodesPage{
		Layout: s.accountLayout(w, r, a, "security", "Save your backup codes"),
		Step:   "show", Codes: res.BackupCodes, FirstFactor: true,
	}
	page.MFARequired = false
	if isHTMX(r) {
		w.Header().Set("HX-Retarget", "#main")
		w.Header().Set("HX-Reswap", "innerHTML")
		s.accountPages.RenderPartial(w, accountui.PageBackupCodes, "main-inner", page)
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageBackupCodes, page)
}

// --- passkey -------------------------------------------------------------------

func (s *Server) handleAccountPasskey(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.mfa.PasskeysEnabled() {
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
		return
	}
	if !s.accountStepUp(w, r, a, r.URL.Path, false) {
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PagePasskey, accountui.PasskeyPage{
		Layout: s.accountLayout(w, r, a, "security", "Add a passkey or security key"),
		API:    "/r/" + a.realm.Name,
	})
}

// --- remove a factor --------------------------------------------------------

// findFactor returns the user's active factor id, and how many they have.
func (s *Server) findFactor(r *http.Request, a *acct, id string) (*domain.MfaMethod, int, error) {
	list, err := s.mfa.ListFactors(r.Context(), a.user.ID)
	if err != nil {
		return nil, 0, err
	}
	for _, m := range list.Methods {
		if m.ID == id {
			return m, len(list.Methods), nil
		}
	}
	return nil, len(list.Methods), nil
}

func (s *Server) handleAccountRemoveFactor(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.accountStepUp(w, r, a, r.URL.Path, false) {
		return
	}
	m, n, err := s.findFactor(r, a, chi.URLParam(r, "methodID"))
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	if m == nil {
		setFlash(w, a.realm.Name, "not_found", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageRemoveFactor, accountui.RemoveFactorPage{
		Layout: s.accountLayout(w, r, a, "security", "Remove"), Factor: factorView(m), Last: n == 1,
	})
}

func (s *Server) handleAccountRemoveFactorConfirm(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	id := chi.URLParam(r, "methodID")
	gate := accountBase(a.realm.Name) + "/security/factors/" + id + "/remove"
	if !s.accountStepUp(w, r, a, gate, false) {
		return
	}
	m, n, err := s.findFactor(r, a, id)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	if m == nil {
		setFlash(w, a.realm.Name, "not_found", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
		return
	}
	err = s.mfa.DeleteFactor(r.Context(), a.user, id)
	switch {
	case errors.Is(err, service.ErrMFARequiredByPolicy):
		s.accountPages.RenderPage(w, http.StatusConflict, accountui.PageRemoveFactor, accountui.RemoveFactorPage{
			Layout: s.accountLayout(w, r, a, "security", "Remove"), Factor: factorView(m), Last: n == 1,
			FormError: a.realm.DisplayName + " requires a second step: add another one before removing this one.",
		})
	case errors.Is(err, service.ErrMFAMethodNotFound):
		setFlash(w, a.realm.Name, "not_found", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
	case err != nil:
		s.accountFailure(w, r, err)
	default:
		setFlash(w, a.realm.Name, "factor_removed", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/security")
	}
}

// --- backup codes --------------------------------------------------------------

func (s *Server) handleAccountBackupCodes(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.accountStepUp(w, r, a, r.URL.Path, false) {
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageBackupCodes, accountui.BackupCodesPage{
		Layout: s.accountLayout(w, r, a, "security", "Get new backup codes"), Step: "confirm",
	})
}

func (s *Server) handleAccountBackupCodesNew(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.accountStepUp(w, r, a, r.URL.Path, false) {
		return
	}
	codes, err := s.mfa.RegenerateBackupCodes(r.Context(), a.user)
	switch {
	case errors.Is(err, service.ErrNoMFAFactor):
		s.accountPages.RenderPage(w, http.StatusConflict, accountui.PageBackupCodes, accountui.BackupCodesPage{
			Layout: s.accountLayout(w, r, a, "security", "Get new backup codes"), Step: "confirm",
			FormError: "Add a second step first: backup codes come with it.",
		})
		return
	case err != nil:
		s.accountFailure(w, r, err)
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageBackupCodes, accountui.BackupCodesPage{
		Layout: s.accountLayout(w, r, a, "security", "Save your backup codes"), Step: "show", Codes: codes,
	})
}

// --- sessions ------------------------------------------------------------------

func (s *Server) sessionsPage(w http.ResponseWriter, r *http.Request, a *acct) (accountui.SessionsPage, error) {
	page := accountui.SessionsPage{Layout: s.accountLayout(w, r, a, "sessions", "Sessions")}
	list, err := s.account.Sessions(r.Context(), a.user, a.sess.ID)
	if err != nil {
		return page, err
	}
	for _, se := range list {
		row := accountui.SessionRow{
			ID: se.ID, Current: se.Current, Device: deviceName(se.UserAgent), Location: locationOf(se.Country),
			IPAddress: se.IPAddress, Method: signInMethod(se), RememberMe: se.RememberMe, Apps: se.Apps,
			StartedAt: se.CreatedAt, LastActiveAt: se.LastActivityAt,
		}
		page.Sessions = append(page.Sessions, row)
	}
	return page, nil
}

func locationOf(country string) string {
	if country == "" {
		return "Unknown location"
	}
	return country
}

// signInMethod words how a session was opened (Session.AuthMethod is an
// RFC 8176 value, the second factor is apart).
func signInMethod(se service.AccountSession) string {
	switch se.AuthMethod {
	case domain.AuthMethodHardwareKey, domain.AuthMethodSoftwareKey:
		return "a passkey"
	}
	out := "your password"
	if se.MFAVerified {
		switch domain.MfaMethodType(se.MFAMethod) {
		case domain.MfaMethodTOTP:
			out += " and an authenticator app"
		case domain.MfaMethodPasskey:
			out += " and a passkey"
		case domain.MfaMethodWebAuthn:
			out += " and a security key"
		case domain.MfaMethodBackupCodes:
			out += " and a backup code"
		default:
			out += " and a second step"
		}
	} else if se.TrustedDevice {
		out += " on a trusted device"
	}
	return out
}

func (s *Server) handleAccountSessions(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	page, err := s.sessionsPage(w, r, a)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageSessions, page)
}

func (s *Server) sessionsAnswer(w http.ResponseWriter, r *http.Request, a *acct, flash string, n int) {
	if !isHTMX(r) {
		setFlash(w, a.realm.Name, flash, n)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/sessions")
		return
	}
	page, err := s.sessionsPage(w, r, a)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	setNotice(&page.Layout, flashValue(flash, n))
	s.renderWithNotice(w, r, accountui.PageSessions, "sessions-list", page, page.Layout)
}

func (s *Server) handleAccountRevokeSession(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	err := s.account.RevokeSession(r.Context(), a.user, a.sess.ID, chi.URLParam(r, "sessionID"), s.accountEvent(r))
	switch {
	case errors.Is(err, service.ErrSessionNotFound), errors.Is(err, service.ErrCurrentSession):
		s.sessionsAnswer(w, r, a, "not_found", 0)
	case err != nil:
		s.accountFailure(w, r, err)
	default:
		s.sessionsAnswer(w, r, a, "session_revoked", 0)
	}
}

func (s *Server) handleAccountRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	n, err := s.account.RevokeOtherSessions(r.Context(), a.user, a.sess.ID, s.accountEvent(r))
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	s.sessionsAnswer(w, r, a, "sessions_revoked", n)
}

// --- connected apps ----------------------------------------------------------

// scopeWords: the standard scopes, in the words of the consent screen.
var scopeWords = map[string]string{
	"profile":        "Your name and profile details",
	"email":          "Your e-mail address",
	"offline_access": "Stay connected while you are signed in here",
	"phone":          "Your phone number",
	"address":        "Your postal address",
}

func (s *Server) appsPage(w http.ResponseWriter, r *http.Request, a *acct) (accountui.AppsPage, error) {
	page := accountui.AppsPage{Layout: s.accountLayout(w, r, a, "apps", "Connected apps")}
	apps, err := s.account.Apps(r.Context(), a.user)
	if err != nil {
		return page, err
	}
	for _, app := range apps {
		row := accountui.AppRow{ClientRef: app.ClientRef, Name: app.Name, Initial: string([]rune(initialsOf(app.Name))[0]),
			Host: app.Host, Consent: app.Consent, GrantedAt: app.GrantedAt, SignedIn: app.SignedIn}
		for _, sc := range app.Scopes {
			text := scopeWords[sc.Name]
			if text == "" {
				text = sc.Description
			}
			if text == "" {
				text = sc.Name
			}
			row.Access = append(row.Access, text)
		}
		page.Apps = append(page.Apps, row)
	}
	return page, nil
}

func (s *Server) handleAccountApps(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	page, err := s.appsPage(w, r, a)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageApps, page)
}

func (s *Server) handleAccountRevokeApp(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	_, err := s.account.RevokeApp(r.Context(), a.user, chi.URLParam(r, "clientRef"), s.accountEvent(r))
	flash := "app_revoked"
	switch {
	case errors.Is(err, service.ErrAppNotFound):
		flash = "not_found"
	case err != nil:
		s.accountFailure(w, r, err)
		return
	}
	if !isHTMX(r) {
		setFlash(w, a.realm.Name, flash, 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/apps")
		return
	}
	page, err := s.appsPage(w, r, a)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	setNotice(&page.Layout, flash)
	s.renderWithNotice(w, r, accountui.PageApps, "apps-list", page, page.Layout)
}

// --- history -------------------------------------------------------------------

var signInResults = map[domain.LoginAttemptFailureReason]string{
	domain.LoginFailureInvalidCredentials: "Wrong password",
	domain.LoginFailureAccountLocked:      "Blocked: account locked",
	domain.LoginFailureMfaFailed:          "Wrong second step",
	domain.LoginFailureTimeoutActive:      "Blocked: access suspended",
	domain.LoginFailureAccessDenied:       "Refused by the application",
	domain.LoginFailurePasskeyRejected:    "Passkey refused",
}

func (s *Server) handleAccountHistory(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	ctx := r.Context()
	view := "signins"
	if r.URL.Query().Get("view") == "activity" {
		view = "activity"
	}
	pageNo, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pageNo < 1 || pageNo > 1000 {
		pageNo = 1
	}
	offset := (pageNo - 1) * historyPageSize
	page := accountui.HistoryPage{Layout: s.accountLayout(w, r, a, "history", "History"), View: view, Page: pageNo}
	if view == "activity" {
		entries, more, err := s.account.Activity(ctx, a.user, offset, historyPageSize)
		if err != nil {
			s.accountFailure(w, r, err)
			return
		}
		page.More = more
		for _, e := range entries {
			row := accountui.ActivityRow{At: e.At, Text: activityText(e), ByAdmin: e.ByAdmin, Failed: e.Failed, IPAddress: e.IPAddress}
			if e.UserAgent != "" {
				row.Device = deviceName(e.UserAgent)
			}
			page.Activity = append(page.Activity, row)
		}
	} else {
		entries, more, err := s.account.SignIns(ctx, a.user, offset, historyPageSize)
		if err != nil {
			s.accountFailure(w, r, err)
			return
		}
		page.More = more
		for _, e := range entries {
			row := accountui.SignInRow{At: e.At, Success: e.Success, Result: "Signed in", Device: deviceName(e.UserAgent),
				Location: locationOf(e.Country), IPAddress: e.IPAddress}
			if !e.Success {
				row.Result = signInResults[e.Reason]
				if row.Result == "" {
					row.Result = "Failed"
				}
			}
			page.SignIns = append(page.SignIns, row)
		}
	}
	s.accountPages.RenderPage(w, http.StatusOK, accountui.PageHistory, page)
}

// activityText words an audit entry for the user (service.AccountActivityActions).
func activityText(e service.ActivityEntry) string {
	detail := func(k string) string {
		v, _ := e.Details[k].(string)
		return v
	}
	factor := func() string {
		switch domain.MfaMethodType(detail("type")) {
		case domain.MfaMethodTOTP:
			return "an authenticator app"
		case domain.MfaMethodPasskey:
			return "a passkey"
		case domain.MfaMethodWebAuthn:
			return "a security key"
		}
		return "a second step"
	}
	switch e.Action {
	case "account.profile_updated":
		return "Name changed"
	case "account.password_changed":
		if e.Failed {
			return "Password change refused (wrong current password)"
		}
		return "Password changed"
	case "account.session_revoked":
		return "A session was signed out"
	case "account.sessions_revoked":
		return "All other sessions were signed out"
	case "account.app_access_revoked":
		if c := detail("client"); c != "" {
			return "Access removed for " + c
		}
		return "Access removed for an application"
	case "account.trusted_device_revoked", "mfa_device_trust_revoked":
		return "A device will ask for the second step again"
	case "account.trusted_devices_revoked":
		return "Every device will ask for the second step again"
	case "mfa_method_enrolled":
		return "Added " + factor()
	case "mfa_method_removed":
		return "Removed " + factor()
	case "mfa_backup_codes_regenerated":
		return "New backup codes"
	case "mfa_device_trusted":
		return "A device no longer asks for the second step"
	case "consent_granted":
		if c := detail("client"); c != "" {
			return "Approved " + c
		}
		return "Approved an application"
	case "consent_revoked":
		if c := detail("client"); c != "" {
			return "Access removed for " + c
		}
		return "Access removed for an application"
	case "known_account.forget":
		return "Account forgotten on a device"
	case "password_reset_requested":
		return "Password reset link requested"
	case "password_reset":
		return "Password reset with an e-mail link"
	case "account_locked":
		return "Account locked after wrong passwords"
	case "admin.user.invite":
		return "Account created"
	case "admin.user.activation_link":
		return "New activation link sent"
	case "admin.user.update":
		return "Account details changed"
	case "admin.user.groups", "admin.user.roles":
		return "Access rights changed"
	case "admin.user.mfa_reset", "mfa_reset":
		return "Second steps reset"
	case "admin.user.unlock":
		return "Account unlocked"
	case "admin.session.revoke_all":
		return "Signed out everywhere"
	case "admin.trusted_device.revoke_all":
		return "Every device will ask for the second step again"
	}
	return "Account updated"
}

// bufferedWriter collects a rendered block (renderWithNotice writes two).
type bufferedWriter struct {
	header http.Header
	body   bytes.Buffer
	failed bool // a block could not be rendered (accountui answered 500)
}

func (b *bufferedWriter) Header() http.Header         { return b.header }
func (b *bufferedWriter) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedWriter) WriteHeader(code int)        { b.failed = b.failed || code >= 500 }
