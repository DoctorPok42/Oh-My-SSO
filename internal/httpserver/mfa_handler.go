package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)


const (
	routeAuthMFA          = "auth.mfa"
	mfaAttemptsPerIP      = 20
	mfaRateLimitWindow    = 15 * time.Minute
	maxMFARequestBodySize = 4 << 10
)

type mfaCodeRequest struct {
	Method string `json:"method"` // "totp" or "backup_code"
	Code   string `json:"code"`
}

type mfaVerifyResponse struct {
	Status               string   `json:"status"`
	UserID               string   `json:"user_id"`
	MFAMethod            string   `json:"mfa_method"`
	AllowedMethods       []string `json:"allowed_methods,omitempty"`
	BackupCodesRemaining *int     `json:"backup_codes_remaining,omitempty"`
}

type mfaErrorResponse struct {
	Error             string `json:"error"`
	AttemptsRemaining *int   `json:"attempts_remaining,omitempty"`
}

type mfaStatusResponse struct {
	Required            bool       `json:"required"`
	Satisfied           bool       `json:"satisfied"`
	EnrollmentRequired  bool       `json:"enrollment_required"`
	EnrollmentDueAt     *time.Time `json:"enrollment_due_at,omitempty"`
	AllowedMethods      []string   `json:"allowed_methods,omitempty"`
	EnrolledMethods     []string   `json:"enrolled_methods"`
	VerifiedMethod      string     `json:"verified_method,omitempty"`
	VerifiedAt          *time.Time `json:"verified_at,omitempty"`
	StepUpFresh         bool       `json:"step_up_fresh"`
	StepUpMaxAgeSeconds int        `json:"step_up_max_age_seconds"`
	Sources             []string   `json:"sources,omitempty"`
}

type stepUpVerifyResponse struct {
	MFAMethod     string    `json:"mfa_method"`
	MFAVerifiedAt time.Time `json:"mfa_verified_at"`
}

type mfaMethodView struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Name       string     `json:"name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type mfaListResponse struct {
	Methods     []mfaMethodView `json:"methods"`
	BackupCodes struct {
		Remaining int `json:"remaining"`
		Total     int `json:"total"`
	} `json:"backup_codes"`
}

type totpStartRequest struct {
	Name string `json:"name"`
}

type totpStartResponse struct {
	MethodID   string    `json:"method_id"`
	Secret     string    `json:"secret"`
	OTPAuthURI string    `json:"otpauth_uri"`
	QRCodePNG  string    `json:"qr_code_png"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type enrollmentResponse struct {
	Method mfaMethodView `json:"method"`
	// BackupCodes: only for the first factor, shown once.
	BackupCodes []string `json:"backup_codes,omitempty"`
}

type backupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

func (s *Server) mountMFA(r chi.Router) {
	r.Route("/auth/mfa", func(r chi.Router) {
		r.With(requireJSON).Post("/verify", s.handleMFAVerify)
		r.With(s.requireSession).Get("/status", s.handleMFAStatus)
	})
	r.With(s.requireSession, requireJSON).Post("/auth/step-up", s.handleStepUp)

	r.Route("/account/mfa", func(r chi.Router) {
		r.Use(s.requireSession)
		account := s.requireStepUp(service.StepUpAccountSecurity)

		r.Get("/", s.handleListMFA)
		r.With(account, requireJSON).Post("/totp", s.handleStartTOTP)
		r.With(requireJSON).Post("/totp/{methodID}/confirm", s.handleConfirmTOTP)
		r.With(account).Delete("/{methodID}", s.handleDeleteMFA)
		r.With(account, requireJSON).Post("/backup-codes", s.handleRegenerateBackupCodes)
	})
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if !s.allowMFAFromIP(w, r, realm.ID) {
		return
	}
	var req mfaCodeRequest
	if !decodeSmallJSON(w, r, &req) || req.Method == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	res, err := s.mfa.VerifyLogin(r.Context(), service.VerifyLoginInput{
		RealmID:        realm.ID,
		ChallengeToken: mfaChallengeTokenFromRequest(r),
		Method:         req.Method,
		Code:           req.Code,
		IPAddress:      clientIP(r),
		UserAgent:      r.UserAgent(),
	})
	if err != nil {
		if errors.Is(err, service.ErrMFAChallengeInvalid) {
			clearMFAChallengeCookie(w, realm.Name)
		}
		s.writeMFAError(w, err)
		return
	}

	s.writeVerifiedLogin(w, r, res)
}

// writeVerifiedLogin ends the second step of a login (code or passkey).
func (s *Server) writeVerifiedLogin(w http.ResponseWriter, r *http.Request, res *service.VerifiedLogin) {
	realmName := realmFromContext(r).Name
	clearMFAChallengeCookie(w, realmName)
	s.endPreviousSession(r, res.Session)
	setSessionCookie(w, realmName, res.RawToken, res.Session)
	out := mfaVerifyResponse{
		Status:    string(res.Outcome),
		UserID:    res.User.ID,
		MFAMethod: string(res.Method),
	}
	if res.Outcome == service.LoginMFAEnrollmentRequired {
		out.AllowedMethods = methodStrings(res.Requirement.AllowedMethods)
	}
	if res.BackupCodesRemaining >= 0 {
		n := res.BackupCodesRemaining
		out.BackupCodesRemaining = &n
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	sess := sessionFromContext(r)

	client, ok := s.clientFromQuery(w, r, realm.ID)
	if !ok {
		return
	}
	st, err := s.mfa.Status(r.Context(), sess, client)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	out := mfaStatusResponse{
		Required:            st.Requirement.Required,
		Satisfied:           st.Satisfied,
		EnrollmentRequired:  st.EnrollmentRequired,
		AllowedMethods:      methodStrings(st.Requirement.AllowedMethods),
		EnrolledMethods:     methodStrings(st.EnrolledMethods),
		VerifiedMethod:      st.VerifiedMethod,
		StepUpFresh:         st.StepUpFresh,
		StepUpMaxAgeSeconds: int(st.StepUpMaxAge.Seconds()),
		Sources:             st.Requirement.Sources,
	}
	if out.EnrolledMethods == nil {
		out.EnrolledMethods = []string{}
	}
	if !st.Requirement.EnrollmentDueAt.IsZero() {
		t := st.Requirement.EnrollmentDueAt
		out.EnrollmentDueAt = &t
	}
	if !st.VerifiedAt.IsZero() {
		t := st.VerifiedAt
		out.VerifiedAt = &t
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	sess := sessionFromContext(r)
	if !s.allowMFAFromIP(w, r, realm.ID) {
		return
	}
	var req mfaCodeRequest
	if !decodeSmallJSON(w, r, &req) || req.Method == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	upd, method, err := s.mfa.StepUp(r.Context(), sess, req.Method, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stepUpVerifyResponse{MFAMethod: string(method), MFAVerifiedAt: upd.MFAVerifiedAt})
}

func (s *Server) handleListMFA(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	list, err := s.mfa.ListFactors(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	out := mfaListResponse{Methods: make([]mfaMethodView, 0, len(list.Methods))}
	for _, m := range list.Methods {
		out.Methods = append(out.Methods, toMFAMethodView(m))
	}
	out.BackupCodes.Remaining = list.BackupCodes.Remaining
	out.BackupCodes.Total = list.BackupCodes.Total
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleStartTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	var req totpStartRequest
	if !decodeSmallJSON(w, r, &req) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	enr, err := s.mfa.StartTOTPEnrollment(r.Context(), user, req.Name)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	// The secret is in this response: never cache it anywhere.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, totpStartResponse{
		MethodID:   enr.MethodID,
		Secret:     enr.Secret,
		OTPAuthURI: enr.URI,
		QRCodePNG:  enr.QRCodePNG,
		ExpiresAt:  enr.ExpiresAt,
	})
}

func (s *Server) handleConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	var req totpConfirmRequest
	if !decodeSmallJSON(w, r, &req) || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	res, err := s.mfa.ConfirmTOTPEnrollment(r.Context(), user, sessionFromContext(r), chi.URLParam(r, "methodID"), req.Code)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, enrollmentResponse{Method: toMFAMethodView(res.Method), BackupCodes: res.BackupCodes})
}

func (s *Server) handleDeleteMFA(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	if err := s.mfa.DeleteFactor(r.Context(), user, chi.URLParam(r, "methodID")); err != nil {
		s.writeMFAError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	codes, err := s.mfa.RegenerateBackupCodes(r.Context(), user)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, backupCodesResponse{BackupCodes: codes})
}

// --- helpers -------------------------------------------------------------------

// writeMFAError maps service errors to HTTP. Every wrong-code case gives
// the same "invalid_mfa_code": never tell wrong from expired or reused.
func (s *Server) writeMFAError(w http.ResponseWriter, err error) {
	var codeErr *service.MFACodeError
	switch {
	case errors.As(err, &codeErr):
		resp := mfaErrorResponse{Error: "invalid_mfa_code"}
		if codeErr.AttemptsRemaining >= 0 {
			n := codeErr.AttemptsRemaining
			resp.AttemptsRemaining = &n
		}
		writeJSON(w, http.StatusUnauthorized, resp)
	case errors.Is(err, service.ErrInvalidMFACode):
		writeError(w, http.StatusUnauthorized, "invalid_mfa_code")
	case errors.Is(err, service.ErrMFAChallengeInvalid):
		writeError(w, http.StatusUnauthorized, "mfa_challenge_expired")
	case errors.Is(err, service.ErrMFAMethodNotAllowed):
		writeError(w, http.StatusBadRequest, "method_not_allowed")
	case errors.Is(err, service.ErrMFARateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, service.ErrMFAEnrollmentExpired):
		writeError(w, http.StatusGone, "enrollment_expired")
	case errors.Is(err, service.ErrMFAMethodNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, service.ErrMFARequiredByPolicy):
		writeError(w, http.StatusConflict, "mfa_required_by_policy")
	case errors.Is(err, service.ErrNoMFAFactor):
		writeError(w, http.StatusConflict, "no_mfa_factor")
	case errors.Is(err, service.ErrMFAPolicyConflict):
		writeError(w, http.StatusForbidden, "mfa_policy_conflict")
	case errors.Is(err, service.ErrInvalidMFAPolicy):
		writeError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, service.ErrSessionInvalid):
		writeError(w, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, service.ErrMFAUnavailable):
		writeError(w, http.StatusServiceUnavailable, "mfa_unavailable")
	case errors.Is(err, service.ErrPasskeysDisabled):
		writeError(w, http.StatusNotFound, "passkeys_disabled")
	case errors.Is(err, service.ErrWebAuthnCeremonyInvalid):
		writeError(w, http.StatusBadRequest, "webauthn_ceremony_expired")
	case errors.Is(err, service.ErrPasskeyRegistrationFailed):
		writeError(w, http.StatusBadRequest, "webauthn_rejected")
	case errors.Is(err, service.ErrPasskeyAlreadyRegistered):
		writeError(w, http.StatusConflict, "already_registered")
	case errors.Is(err, service.ErrUnknownPasskeyKind):
		writeError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, service.ErrNoPasskeyForSignIn):
		writeError(w, http.StatusConflict, "passkey_unavailable")
	case errors.Is(err, service.ErrPasskeySignInFailed),
		errors.Is(err, service.ErrAccountNotActive),
		errors.Is(err, service.ErrTimeoutActive):
		// One answer for all three, like a wrong password.
		writeError(w, http.StatusUnauthorized, "passkey_rejected")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func (s *Server) allowMFAFromIP(w http.ResponseWriter, r *http.Request, realmID string) bool {
	if s.rateLimiter == nil {
		return true
	}
	ok, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.Key(routeAuthMFA, realmID, "ip", clientIP(r)),
		mfaAttemptsPerIP, mfaRateLimitWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return false
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return false
	}
	return true
}

func (s *Server) sessionUser(w http.ResponseWriter, r *http.Request) (*domain.User, bool) {
	user, err := s.mfa.User(r.Context(), sessionFromContext(r).UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return nil, false
	}
	return user, true
}

func (s *Server) clientFromQuery(w http.ResponseWriter, r *http.Request, realmID string) (*domain.ClientApp, bool) {
	return s.lookupAnyClient(w, r, realmID, r.URL.Query().Get("client_id"), r.URL.Query().Get("entity_id"))
}

// lookupAnyClient resolves the application a login is for, named by its
// OIDC client_id or its SAML entity_id (at most one of them). Neither: nil.
func (s *Server) lookupAnyClient(w http.ResponseWriter, r *http.Request, realmID, clientID, entityID string) (*domain.ClientApp, bool) {
	switch {
	case clientID != "" && entityID != "":
		writeError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	case clientID != "":
		return s.lookupClient(w, r, realmID, clientID)
	case entityID != "":
		c, err := s.clients.GetByRealmAndEntityID(r.Context(), realmID, entityID)
		return s.checkClient(w, c, err)
	default:
		return nil, true
	}
}

func (s *Server) lookupClient(w http.ResponseWriter, r *http.Request, realmID, clientID string) (*domain.ClientApp, bool) {
	c, err := s.clients.GetByRealmAndClientID(r.Context(), realmID, clientID)
	return s.checkClient(w, c, err)
}

// checkClient turns a repository lookup into "an active client, or an error
// response already written".
func (s *Server) checkClient(w http.ResponseWriter, c *domain.ClientApp, err error) (*domain.ClientApp, bool) {
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown_client")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "internal_error")
		return nil, false
	}
	if c.IsDeleted() || c.Status != domain.ClientAppActive {
		writeError(w, http.StatusBadRequest, "unknown_client")
		return nil, false
	}
	return c, true
}

// decodeSmallJSON reads a small JSON body; an empty body decodes to the zero
// value. Unknown fields are refused, so a typo is never silently ignored.
func decodeSmallJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMFARequestBodySize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return true
}

func toMFAMethodView(m *domain.MfaMethod) mfaMethodView {
	v := mfaMethodView{ID: m.ID, Type: string(m.Type), Name: m.Name, CreatedAt: m.CreatedAt}
	if !m.LastUsedAt.IsZero() {
		t := m.LastUsedAt
		v.LastUsedAt = &t
	}
	return v
}

func methodStrings(in []domain.MfaMethodType) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, m := range in {
		out = append(out, string(m))
	}
	return out
}
