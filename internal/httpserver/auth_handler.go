package httpserver

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/clientip"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)

const (
	routeAuthLogin = "auth.login"

	loginAttemptsPerIP   = 20
	loginRateLimitWindow = 15 * time.Minute

	// maxLoginRequestBodySize: a login request is a few hundred bytes. The
	// limit stops a client from making the server read (and hash) megabytes.
	maxLoginRequestBodySize = 8 << 10
)

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	ClientID string `json:"client_id,omitempty"`
	EntityID string `json:"entity_id,omitempty"`
	// RememberMe: "Keep me signed in" is ticked. Ignored when the realm
	// does not offer it.
	RememberMe bool `json:"remember_me,omitempty"`
	// AccountID: the password was typed on this tile of "Pick an account"
	AccountID string `json:"account_id,omitempty"`
}

// loginResponse. "status" tells the next step:
//
//	authenticated           session cookie set, done
//	mfa_required            no session yet: POST /auth/mfa/verify with one of "methods"
//	mfa_enrollment_required session cookie set, but a policy requires MFA and
//	                        the user has no allowed factor: enroll one first
type loginResponse struct {
	Status             string   `json:"status"`
	UserID             string   `json:"user_id,omitempty"`
	Methods            []string `json:"methods,omitempty"`
	AllowedMethods     []string `json:"allowed_methods,omitempty"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	MFAEnrollmentDueAt string   `json:"mfa_enrollment_due_at,omitempty"`
	// RememberMe: the session is a remembered one (persistent cookie).
	RememberMe bool `json:"remember_me,omitempty"`
	// mfa_required: the page may offer "Don't ask again on this device"
	// for that many days (absent: no box). authenticated: TrustedDevice
	// tells the second factor was skipped, the device is trusted.
	TrustDeviceDays int  `json:"trust_device_days,omitempty"`
	TrustedDevice   bool `json:"trusted_device,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type sessionResponse struct {
	SessionID     string     `json:"session_id"`
	UserID        string     `json:"user_id"`
	AuthMethod    string     `json:"auth_method"`
	MFAVerified   bool       `json:"mfa_verified"`
	MFAMethod     string     `json:"mfa_method,omitempty"`
	MFAVerifiedAt *time.Time `json:"mfa_verified_at,omitempty"`
	RememberMe    bool       `json:"remember_me"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

func (s *Server) mountAuth(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		// requireJSON stops "login CSRF": without it, a foreign page could
		// submit a hidden form (enctype="text/plain" whose body looks like
		// JSON) and sign the visitor's browser in to the attacker's account.
		r.With(requireJSON).Post("/login", s.handleLogin)
		// Logout needs no such check: the SameSite=Lax session cookie is
		// not sent with a cross-site POST, so a foreign page cannot end
		// someone's session.
		r.Post("/logout", s.handleLogout)
		if s.accounts != nil {
			r.With(requireJSON).Post("/accounts/forget", s.handleForgetAccount)
		}

		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Get("/session", s.handleGetSession)
		})
	})
}

// rememberPasswordChoice: a correct password typed on a tile that also
// offered a passkey. On this device, the tile now starts with the password
func (s *Server) rememberPasswordChoice(r *http.Request, realmID string, user *domain.User, client *domain.ClientApp, accountID string) {
	if accountID == "" || s.accounts == nil || s.mfa == nil {
		return
	}
	offered, err := s.mfa.SignInMethods(r.Context(), user, client)
	if err != nil {
		return // cannot tell whether a passkey was offered: remember nothing
	}
	s.accounts.PasswordChosen(r.Context(), service.PasswordChosenInput{
		RealmID: realmID, DeviceID: deviceIDFromRequest(r), AccountID: accountID, UserID: user.ID, Offered: offered,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	var req loginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginRequestBodySize))
	if err := dec.Decode(&req); err != nil || req.Identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// No password longer than service.MaxPasswordLength can be set, so a
	// longer one is never right: refuse it before it reaches Argon2id.
	if len(req.Password) > maxPasswordLen {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	ip := clientIP(r)

	byIP, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.Key(routeAuthLogin, realm.ID, "ip", ip),
		loginAttemptsPerIP, loginRateLimitWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !byIP {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	client, ok := s.lookupAnyClient(w, r, realm.ID, req.ClientID, req.EntityID)
	if !ok {
		return
	}
	clientRef := ""
	if client != nil {
		clientRef = client.ID
	}

	user, err := s.auth.AuthenticateLocal(r.Context(), service.AuthenticateLocalParams{
		RealmID:    realm.ID,
		Identifier: req.Identifier,
		Password:   req.Password,
		IPAddress:  ip,
		UserAgent:  r.UserAgent(),
		ClientRef:  clientRef,
	})
	if err != nil {
		var locked *service.AccountLockedError
		switch {
		case errors.As(err, &locked):
			writeRetryAfter(w, locked.Until)
		case errors.Is(err, service.ErrTimeoutActive):
			// Only returned after a correct password: saying so reveals
			// nothing to someone who does not know it.
			writeTimeoutError(w, err)
		case errors.Is(err, service.ErrInvalidCredentials),
			errors.Is(err, service.ErrAccountNotActive):
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	resp := loginResponse{Status: string(service.LoginAuthenticated), UserID: user.ID}
	device := service.DeviceFingerprint(ensureDeviceCookie(w, r, realm.Name))
	s.rememberPasswordChoice(r, realm.ID, user, client, req.AccountID)

	if s.mfa != nil {
		dec, err := s.mfa.BeginLogin(r.Context(), service.BeginLoginInput{
			User:              user,
			Client:            client,
			IPAddress:         ip,
			UserAgent:         r.UserAgent(),
			DeviceFingerprint: device,
			RememberMe:        req.RememberMe,
		})
		if err != nil {
			s.writeMFAError(w, err)
			return
		}
		if !dec.Requirement.EnrollmentDueAt.IsZero() {
			resp.MFAEnrollmentDueAt = dec.Requirement.EnrollmentDueAt.UTC().Format(time.RFC3339)
		}
		switch dec.Outcome {
		case service.LoginMFARequired:
			setMFAChallengeCookie(w, realm.Name, dec.ChallengeToken, dec.ChallengeExpiresAt)
			writeJSON(w, http.StatusOK, loginResponse{
				Status:          string(dec.Outcome),
				Methods:         methodStrings(dec.Methods),
				ExpiresAt:       dec.ChallengeExpiresAt.UTC().Format(time.RFC3339),
				TrustDeviceDays: dec.TrustDeviceDays,
			})
			return
		case service.LoginMFAEnrollmentRequired:
			resp.Status = string(dec.Outcome)
			resp.AllowedMethods = methodStrings(dec.Methods)
		}
		resp.TrustedDevice = dec.TrustedDevice
	}

	rawToken, sess, err := s.sessions.Create(r.Context(), service.CreateSessionInput{
		RealmID:           realm.ID,
		UserID:            user.ID,
		IPAddress:         ip,
		UserAgent:         r.UserAgent(),
		AuthMethod:        domain.AuthMethodPassword,
		DeviceFingerprint: device,
		RememberMe:        req.RememberMe,
		TrustedDevice:     resp.TrustedDevice,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	s.endPreviousSession(r, sess)
	setSessionCookie(w, realm.Name, rawToken, sess)
	rememberRealm(w, r, realm.Name) // the account console's organization menu
	resp.RememberMe = sess.RememberMe
	writeJSON(w, http.StatusOK, resp)
}

// endPreviousSession: one signed-in account per browser and realm. When
// another account signs in ("Use another account"), the browser's previous
// session is ended: it would otherwise stay signed in where nobody sees it.
// The same user signing in again (prompt=login) keeps it: its other
// applications' refresh tokens are bound to it.
func (s *Server) endPreviousSession(r *http.Request, next *domain.Session) {
	raw := sessionTokenFromRequest(r)
	if raw == "" {
		return
	}
	prev, err := s.sessions.Validate(r.Context(), next.RealmID, raw)
	if err != nil || prev.ID == next.ID || prev.UserID == next.UserID {
		return
	}
	if err := s.sessions.EndSession(r.Context(), prev, domain.SessionRevokedAccountSwitch, service.LogoutEvent{
		Via: domain.LogoutViaAccountSwitch, IPAddress: clientIP(r), UserAgent: r.UserAgent(),
	}); err != nil {
		slog.WarnContext(r.Context(), "end the previous session of the browser", "session_id", prev.ID, "error", err)
	}
}

type forgetAccountRequest struct {
	AccountID string `json:"account_id"`
}

// handleForgetAccount: "Forget" (or "Sign out and forget") on a tile of
// "Pick an account". Only the accounts of this browser's device can be
// removed. When the account is the one signed in here, it is signed out.
func (s *Server) handleForgetAccount(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	var req forgetAccountRequest
	if !decodeSmallJSON(w, r, &req) || req.AccountID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	acc, err := s.accounts.Forget(r.Context(), service.ForgetAccountInput{
		RealmID: realm.ID, DeviceID: deviceIDFromRequest(r), AccountID: req.AccountID,
		IPAddress: clientIP(r), UserAgent: r.UserAgent(),
	})
	if errors.Is(err, service.ErrKnownAccountNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if raw := sessionTokenFromRequest(r); raw != "" {
		if sess, err := s.sessions.Validate(r.Context(), realm.ID, raw); err == nil && sess.UserID == acc.UserID {
			if err := s.sessions.EndSession(r.Context(), sess, domain.SessionRevokedUserLogout, service.LogoutEvent{
				Via: domain.LogoutViaForget, IPAddress: clientIP(r), UserAgent: r.UserAgent(),
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "internal_error")
				return
			}
			clearSessionCookie(w, realm.Name)
			forgetRealm(w, r, realm.Name)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	if err := s.sessions.Logout(r.Context(), sessionTokenFromRequest(r), service.LogoutEvent{
		Via: domain.LogoutViaAPI, IPAddress: clientIP(r), UserAgent: r.UserAgent(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	clearSessionCookie(w, realm.Name)
	forgetRealm(w, r, realm.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	out := sessionResponse{
		SessionID:   sess.ID,
		UserID:      sess.UserID,
		AuthMethod:  sess.AuthMethod,
		MFAVerified: sess.MFAVerified,
		MFAMethod:   sess.MFAMethodType,
		RememberMe:  sess.RememberMe,
		ExpiresAt:   sess.ExpiresAt,
	}
	if !sess.MFAVerifiedAt.IsZero() {
		t := sess.MFAVerifiedAt
		out.MFAVerifiedAt = &t
	}
	writeJSON(w, http.StatusOK, out)
}

// clientIP is the address the request comes from: the TCP peer, or the
// address a trusted reverse proxy reported (see internal/clientip).
func clientIP(r *http.Request) string {
	return clientip.FromRequest(r)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorResponse{Error: code})
}

// writeTimeoutError answers 403 for an administrator's timeout, once the
// user proved who they are: "access_suspended" (the user or one of their
// groups) or "client_unavailable" (the application). Neither the reason nor
// the end is sent.
func writeTimeoutError(w http.ResponseWriter, err error) {
	code := "access_suspended"
	if core.TimeoutOnClient(err) {
		code = "client_unavailable"
	}
	writeError(w, http.StatusForbidden, code)
}

// writeRetryAfter answers 429 "rate_limited" with the seconds left in the
// Retry-After header (RFC 9110 §10.2.3). The body stays the usual
// {"error": ...}, so clients need nothing new.
func writeRetryAfter(w http.ResponseWriter, until time.Time) {
	secs := int(math.Ceil(time.Until(until).Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "rate_limited")
}
