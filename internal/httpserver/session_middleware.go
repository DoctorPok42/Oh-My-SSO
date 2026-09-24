package httpserver

import (
	"context"
	"errors"
	"net/http"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

type sessionContextKey struct{}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)

		rawToken := sessionTokenFromRequest(r)
		if rawToken == "" {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		sess, err := s.sessions.Validate(r.Context(), realm.ID, rawToken)
		if err != nil {
			if errors.Is(err, service.ErrSessionInvalid) {
				clearSessionCookie(w, realm.Name)
				writeError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey{}, sess)
		ctx = audit.WithActor(ctx, audit.Actor{UserID: sess.UserID, RealmID: sess.RealmID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sessionFromContext(r *http.Request) *domain.Session {
	sess, _ := r.Context().Value(sessionContextKey{}).(*domain.Session)
	return sess
}
