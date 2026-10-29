package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)


const maxWebAuthnBodySize = 64 << 10

type passkeyRegisterRequest struct {
	Kind string `json:"kind"` // "passkey" (default) or "security_key"
	Name string `json:"name"`
}

func (s *Server) mountWebAuthn(r chi.Router) {
	r.Route("/auth/mfa/webauthn", func(r chi.Router) {
		r.Use(requireJSON)
		r.Post("/options", s.handlePasskeyLoginOptions)
		r.Post("/verify", s.handlePasskeyLoginVerify)
	})
	// user verification replaces the password and the second factor.
	r.Route("/auth/passkey", func(r chi.Router) {
		r.Use(requireJSON)
		r.Post("/options", s.handlePasskeySignInOptions)
		r.Post("/verify", s.handlePasskeySignInVerify)
	})
	r.Route("/auth/step-up/webauthn", func(r chi.Router) {
		r.Use(s.requireSession, requireJSON)
		r.Post("/options", s.handlePasskeyStepUpOptions)
		r.Post("/verify", s.handlePasskeyStepUpVerify)
	})
	r.Route("/account/mfa/webauthn/register", func(r chi.Router) {
		r.Use(s.requireSession, requireJSON)
		r.With(s.requireStepUp(service.StepUpAccountSecurity)).Post("/options", s.handlePasskeyRegisterOptions)
		r.Post("/verify", s.handlePasskeyRegisterVerify)
	})
}

func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	options, err := s.mfa.BeginPasskeyLogin(r.Context(), realm.ID, mfaChallengeTokenFromRequest(r))
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeRawJSON(w, options)
}

func (s *Server) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if !s.allowMFAFromIP(w, r, realm.ID) {
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	// The body is the credential itself, or {"credential": ..., "trust_device":
	var wrapped struct {
		Credential  json.RawMessage `json:"credential"`
		TrustDevice bool            `json:"trust_device"`
	}
	if json.Unmarshal(body, &wrapped) == nil && len(wrapped.Credential) > 0 {
		body = wrapped.Credential
	}
	res, err := s.mfa.FinishPasskeyLogin(r.Context(), service.VerifyPasskeyLoginInput{
		RealmID:        realm.ID,
		ChallengeToken: mfaChallengeTokenFromRequest(r),
		Response:       body,
		IPAddress:      clientIP(r),
		UserAgent:      r.UserAgent(),
		TrustDevice:    wrapped.TrustDevice,
	})
	if err != nil {
		if err == service.ErrMFAChallengeInvalid {
			clearMFAChallengeCookie(w, realm.Name)
		}
		s.writeMFAError(w, err)
		return
	}
	s.writeVerifiedLogin(w, r, res)
}

func (s *Server) handlePasskeyStepUpOptions(w http.ResponseWriter, r *http.Request) {
	options, err := s.mfa.BeginPasskeyStepUp(r.Context(), sessionFromContext(r))
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeRawJSON(w, options)
}

func (s *Server) handlePasskeyStepUpVerify(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if !s.allowMFAFromIP(w, r, realm.ID) {
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	upd, method, err := s.mfa.FinishPasskeyStepUp(r.Context(), sessionFromContext(r), body, clientIP(r), r.UserAgent())
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stepUpVerifyResponse{MFAMethod: string(method), MFAVerifiedAt: upd.MFAVerifiedAt})
}

func (s *Server) handlePasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	var req passkeyRegisterRequest
	if !decodeSmallJSON(w, r, &req) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	kind := service.PasskeyKind(req.Kind)
	if kind == "" {
		kind = service.PasskeyKindPasskey
	}
	options, err := s.mfa.BeginPasskeyRegistration(r.Context(), user, sessionFromContext(r), kind, req.Name)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeRawJSON(w, options)
}

func (s *Server) handlePasskeyRegisterVerify(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	res, err := s.mfa.FinishPasskeyRegistration(r.Context(), user, sessionFromContext(r), body)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, enrollmentResponse{Method: toMFAMethodView(res.Method), BackupCodes: res.BackupCodes})
}

const (
	routeAuthPasskeyOptions = "auth.passkey.options"
	// passkeyOptionsPerIP: each call stores a ceremony for 5 minutes.
	passkeyOptionsPerIP = 30
)

// passkeySignInOptionsRequest. AccountID: the tile of "Pick an account"
// (only this device's tiles); empty: any passkey of the browser.
type passkeySignInOptionsRequest struct {
	AccountID string `json:"account_id,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	EntityID  string `json:"entity_id,omitempty"`
}

type passkeySignInVerifyRequest struct {
	Credential json.RawMessage `json:"credential"`
	RememberMe bool            `json:"remember_me,omitempty"`
}

// handlePasskeySignInOptions starts a sign-in without password. The
// ceremony token goes in an HttpOnly cookie: only this browser can answer.
func (s *Server) handlePasskeySignInOptions(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if s.mfa == nil || !s.mfa.PasskeysEnabled() {
		writeError(w, http.StatusNotFound, "passkeys_disabled")
		return
	}
	ok, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.Key(routeAuthPasskeyOptions, realm.ID, "ip", clientIP(r)),
		passkeyOptionsPerIP, loginRateLimitWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var req passkeySignInOptionsRequest
	if !decodeSmallJSON(w, r, &req) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client, ok := s.lookupAnyClient(w, r, realm.ID, req.ClientID, req.EntityID)
	if !ok {
		return
	}

	in := service.BeginPasswordlessInput{RealmID: realm.ID, Client: client}
	if req.AccountID != "" {
		if s.accounts == nil {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		acc, err := s.accounts.Resolve(r.Context(), realm.ID, deviceIDFromRequest(r), req.AccountID)
		if errors.Is(err, service.ErrKnownAccountNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		if in.User, err = s.mfa.User(r.Context(), acc.UserID); err != nil {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
	}

	c, err := s.mfa.BeginPasswordlessLogin(r.Context(), in)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	setPasskeyCeremonyCookie(w, realm.Name, c.Token, c.ExpiresAt)
	writeRawJSON(w, c.Options)
}

// handlePasskeySignInVerify checks the answer and signs in: same response as
// POST /auth/mfa/verify ("authenticated", or "mfa_enrollment_required" when
// the application wants a method the user has not enrolled).
func (s *Server) handlePasskeySignInVerify(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if s.mfa == nil || !s.mfa.PasskeysEnabled() {
		writeError(w, http.StatusNotFound, "passkeys_disabled")
		return
	}
	// The same budget as the passwords of this address.
	ok, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.Key(routeAuthLogin, realm.ID, "ip", clientIP(r)),
		loginAttemptsPerIP, loginRateLimitWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	var req passkeySignInVerifyRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Credential) == 0 || req.Credential[0] != '{' {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	token := passkeyCeremonyTokenFromRequest(r)
	clearPasskeyCeremonyCookie(w, realm.Name) // single use, whatever happens
	device := service.DeviceFingerprint(ensureDeviceCookie(w, r, realm.Name))
	res, err := s.mfa.FinishPasswordlessLogin(r.Context(), service.FinishPasswordlessInput{
		RealmID:           realm.ID,
		Token:             token,
		Response:          req.Credential,
		IPAddress:         clientIP(r),
		UserAgent:         r.UserAgent(),
		DeviceFingerprint: device,
		RememberMe:        req.RememberMe,
	})
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	if s.accounts != nil {
		s.accounts.PasskeySignIn(r.Context(), realm.ID, device, res.User.ID)
	}
	s.writeVerifiedLogin(w, r, res)
}

func readWebAuthnBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize))
	if err != nil || !json.Valid(body) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

// writeRawJSON sends JSON already encoded by the WebAuthn library.
func writeRawJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
