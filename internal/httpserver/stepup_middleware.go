package httpserver

import (
	"errors"
	"net/http"

	"sso.internal/sso/internal/core/service"
)

// stepUpResponse tells the client what kind of re-authentication is needed.
type stepUpResponse struct {
	Error          string   `json:"error"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	MaxAgeSeconds  int      `json:"max_age_seconds"`
}

func (s *Server) requireStepUp(mode service.StepUpMode) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if s.mfa == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := sessionFromContext(r)
			if sess == nil {
				writeError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			err := s.mfa.CheckStepUp(r.Context(), sess, mode)
			var su *service.StepUpRequiredError
			switch {
			case err == nil:
				next.ServeHTTP(w, r)
			case errors.As(err, &su):
				code := "step_up_required"
				switch su.Reason {
				case service.StepUpNeedRecentLogin:
					code = "recent_login_required"
				case service.StepUpNeedEnrollment:
					code = "mfa_enrollment_required"
				}
				writeJSON(w, http.StatusForbidden, stepUpResponse{
					Error:          code,
					AllowedMethods: methodStrings(su.AllowedMethods),
					MaxAgeSeconds:  int(su.MaxAge.Seconds()),
				})
			default:
				writeError(w, http.StatusInternalServerError, "internal_error")
			}
		})
	}
}
