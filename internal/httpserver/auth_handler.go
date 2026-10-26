package httpserver

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)

const (
	routeAuthLogin = "auth.login"

	loginAttemptsPerIP   = 20
	loginRateLimitWindow = 15 * time.Minute
)

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	ClientID string `json:"client_id,omitempty"`
	EntityID string `json:"entity_id,omitempty"`
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
	ExpiresAt     time.Time  `json:"expires_at"`
}

func (s *Server) mountAuth(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", s.handleLogin)
		r.Post("/logout", s.handleLogout)

		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Get("/session", s.handleGetSession)
		})
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Identifier == "" || req.Password == "" {
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
		case errors.Is(err, service.ErrInvalidCredentials),
			errors.Is(err, service.ErrAccountNotActive),
			errors.Is(err, service.ErrTimeoutActive):
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	resp := loginResponse{Status: string(service.LoginAuthenticated), UserID: user.ID}
	device := service.DeviceFingerprint(ensureDeviceCookie(w, r, realm.Name))

	if s.mfa != nil {
		dec, err := s.mfa.BeginLogin(r.Context(), service.BeginLoginInput{
			User:              user,
			Client:            client,
			IPAddress:         ip,
			UserAgent:         r.UserAgent(),
			DeviceFingerprint: device,
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
				Status:    string(dec.Outcome),
				Methods:   methodStrings(dec.Methods),
				ExpiresAt: dec.ChallengeExpiresAt.UTC().Format(time.RFC3339),
			})
			return
		case service.LoginMFAEnrollmentRequired:
			resp.Status = string(dec.Outcome)
			resp.AllowedMethods = methodStrings(dec.Methods)
		}
	}

	rawToken, sess, err := s.sessions.Create(r.Context(), service.CreateSessionInput{
		RealmID:           realm.ID,
		UserID:            user.ID,
		IPAddress:         ip,
		UserAgent:         r.UserAgent(),
		AuthMethod:        domain.AuthMethodPassword,
		DeviceFingerprint: device,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	setSessionCookie(w, realm.Name, rawToken, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	if err := s.sessions.Logout(r.Context(), sessionTokenFromRequest(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	clearSessionCookie(w, realm.Name)
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
		ExpiresAt:   sess.ExpiresAt,
	}
	if !sess.MFAVerifiedAt.IsZero() {
		t := sess.MFAVerifiedAt
		out.MFAVerifiedAt = &t
	}
	writeJSON(w, http.StatusOK, out)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorResponse{Error: code})
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
