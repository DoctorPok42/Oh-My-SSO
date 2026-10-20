package httpserver

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)

// Password reset routes (Step 12).
//
//	GET  /r/{realm}/auth/forgot-password   page: "enter your username or e-mail"
//	POST /r/{realm}/auth/forgot-password   {identifier}       → 202, always
//	GET  /r/{realm}/auth/reset-password    page: "choose a new password" (token in #fragment)
//	POST /r/{realm}/auth/reset-password    {token, password}  → 200 | 400
//	GET  /r/{realm}/auth/assets/{file}     CSS and JS of the pages

const (
	routeForgotPassword = "auth.forgot_password"
	routeResetPassword  = "auth.reset_password"

	// Anti "e-mail bombing": nobody can flood a mailbox with reset links.
	forgotPerIdentifier = 3
	forgotPerIP         = 10
	forgotWindow        = time.Hour
	// Reset tokens are 256 random bits (guessing is hopeless); the limit
	// only keeps the endpoint cheap.
	resetPerIP     = 20
	resetWindow    = 15 * time.Minute
	maxPasswordLen = 4 * service.MaxPasswordLength // bytes: 4 per UTF-8 character at most
)

type forgotPasswordRequest struct {
	Identifier string `json:"identifier"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type passwordPolicyErrorResponse struct {
	Error     string `json:"error"`
	MinLength int    `json:"min_length"`
	MaxLength int    `json:"max_length"`
}

func (s *Server) mountPasswordReset(r chi.Router) {
	pages, err := loginui.New(nil)
	if err != nil {
		panic("httpserver: login pages: " + err.Error()) // embedded templates: a bug, not a runtime error
	}
	// Full paths (not r.Route("/auth")): mountAuth already owns that sub-router.
	r.Get("/auth/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		pages.RenderForgotPassword(w, loginui.ForgotPassword{
			RealmDisplay: realmDisplay(realm.DisplayName, realm.Name),
			Base:         "/r/" + realm.Name,
			Assets:       "/r/" + realm.Name + "/auth/assets",
		})
	})
	r.Get("/auth/reset-password", func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		pages.RenderResetPassword(w, loginui.ResetPassword{
			RealmDisplay: realmDisplay(realm.DisplayName, realm.Name),
			Base:         "/r/" + realm.Name,
			Assets:       "/r/" + realm.Name + "/auth/assets",
			MinLength:    s.passwordReset.MinPasswordLength(r.Context(), realm.ID),
			MaxLength:    service.MaxPasswordLength,
		})
	})
	r.Get("/auth/assets/{file}", func(w http.ResponseWriter, r *http.Request) {
		loginui.Asset(w, r, chi.URLParam(r, "file"))
	})
	r.With(requireJSON).Post("/auth/forgot-password", s.handleForgotPassword)
	r.With(requireJSON).Post("/auth/reset-password", s.handleResetPassword)
}

// handleForgotPassword never says whether the account exists: same status,
// same body, and the same (short) time, since the lookup and the e-mail
// happen in the background (RequestResetAsync).
func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	var req forgotPasswordRequest
	if !decodeSmallJSON(w, r, &req) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || len(identifier) > 320 { // 320: longest possible e-mail address
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	ip := clientIP(r)
	ok, err := s.allowAll(r,
		limit{ratelimit.Key(routeForgotPassword, realm.ID, "identifier", strings.ToLower(identifier)), forgotPerIdentifier, forgotWindow},
		limit{ratelimit.Key(routeForgotPassword, realm.ID, "ip", ip), forgotPerIP, forgotWindow},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	s.passwordReset.RequestResetAsync(r.Context(), service.RequestResetInput{
		RealmID:    realm.ID,
		Identifier: identifier,
		IPAddress:  ip,
		UserAgent:  r.UserAgent(),
	})
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	var req resetPasswordRequest
	if !decodeSmallJSON(w, r, &req) || req.Token == "" || req.Password == "" || len(req.Password) > maxPasswordLen {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ok, err := s.allowAll(r, limit{ratelimit.Key(routeResetPassword, realm.ID, "ip", clientIP(r)), resetPerIP, resetWindow})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	err = s.passwordReset.ResetPassword(r.Context(), service.ResetPasswordInput{
		RealmID:     realm.ID,
		Token:       req.Token,
		NewPassword: req.Password,
		IPAddress:   clientIP(r),
		UserAgent:   r.UserAgent(),
	})
	var policyErr *service.PasswordPolicyError
	switch {
	case err == nil:
		// The user's sessions are all revoked, this browser's included.
		clearSessionCookie(w, realm.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
	case errors.Is(err, service.ErrResetTokenInvalid):
		writeError(w, http.StatusBadRequest, "invalid_or_expired_token")
	case errors.As(err, &policyErr):
		writeJSON(w, http.StatusBadRequest, passwordPolicyErrorResponse{
			Error:     passwordPolicyCode(policyErr),
			MinLength: policyErr.MinLength,
			MaxLength: policyErr.MaxLength,
		})
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func passwordPolicyCode(err *service.PasswordPolicyError) string {
	switch {
	case errors.Is(err, service.ErrPasswordTooShort):
		return "password_too_short"
	case errors.Is(err, service.ErrPasswordTooLong):
		return "password_too_long"
	case errors.Is(err, service.ErrPasswordMatchesIdentity):
		return "password_matches_identity"
	default:
		return "password_rejected"
	}
}

type limit struct {
	key    string
	max    int64
	window time.Duration
}

// allowAll checks every limit (and counts the request in each).
func (s *Server) allowAll(r *http.Request, limits ...limit) (bool, error) {
	allowed := true
	for _, l := range limits {
		ok, err := s.rateLimiter.Allow(r.Context(), l.key, l.max, l.window)
		if err != nil {
			return false, err
		}
		allowed = allowed && ok
	}
	return allowed, nil
}

func realmDisplay(display, name string) string {
	if display != "" {
		return display
	}
	return name
}
