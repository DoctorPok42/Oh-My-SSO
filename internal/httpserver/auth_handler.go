package httpserver

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)

const (
	routeAuthLogin = "auth.login"

	loginAttemptsPerIdentifier = 5
	loginAttemptsPerIP         = 20
	loginRateLimitWindow       = 15 * time.Minute
)

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type loginResponse struct {
	UserID string `json:"user_id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type sessionResponse struct {
	SessionID   string    `json:"session_id"`
	UserID      string    `json:"user_id"`
	AuthMethod  string    `json:"auth_method"`
	MFAVerified bool      `json:"mfa_verified"`
	ExpiresAt   time.Time `json:"expires_at"`
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

	byIdentifier, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.Key(routeAuthLogin, realm.ID, "identifier", req.Identifier),
		loginAttemptsPerIdentifier, loginRateLimitWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	byIP, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.Key(routeAuthLogin, realm.ID, "ip", ip),
		loginAttemptsPerIP, loginRateLimitWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !byIdentifier || !byIP {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	user, err := s.auth.AuthenticateLocal(r.Context(), service.AuthenticateLocalParams{
		RealmID:    realm.ID,
		Identifier: req.Identifier,
		Password:   req.Password,
		IPAddress:  ip,
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrAccountNotActive):
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	rawToken, sess, err := s.sessions.Create(r.Context(), service.CreateSessionInput{
		RealmID:    realm.ID,
		UserID:     user.ID,
		IPAddress:  ip,
		UserAgent:  r.UserAgent(),
		AuthMethod: "password",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	setSessionCookie(w, realm.Name, rawToken, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, loginResponse{UserID: user.ID})
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
	writeJSON(w, http.StatusOK, sessionResponse{
		SessionID:   sess.ID,
		UserID:      sess.UserID,
		AuthMethod:  sess.AuthMethod,
		MFAVerified: sess.MFAVerified,
		ExpiresAt:   sess.ExpiresAt,
	})
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
