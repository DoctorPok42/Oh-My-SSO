package httpserver

import (
	"context"
	"errors"
	"net/http"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

type Authorizer interface {
	Authorize(ctx context.Context, in service.AuthorizeInput) error
}

func (s *Server) requirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			realm := realmFromContext(r)
			if realm == nil {
				writeError(w, http.StatusInternalServerError, "internal_error")
				return
			}
			sess := sessionFromContext(r)
			if sess == nil {
				writeError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}

			clientRef, err := s.internalClientRef(r.Context(), realm.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal_error")
				return
			}

			err = s.authz.Authorize(r.Context(), service.AuthorizeInput{
				RealmID:   realm.ID,
				UserID:    sess.UserID,
				ClientRef: clientRef,
				Resource:  resource,
				Action:    action,
				IPAddress: clientIP(r),
				UserAgent: r.UserAgent(),
			})
			switch {
			case errors.Is(err, service.ErrForbidden):
				writeError(w, http.StatusForbidden, "forbidden")
				return
			case err != nil:
				writeError(w, http.StatusInternalServerError, "internal_error")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) internalClientRef(ctx context.Context, realmID string) (string, error) {
	c, err := s.clients.GetByRealmAndClientID(ctx, realmID, domain.InternalAdminClientID)
	if errors.Is(err, repository.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return c.ID, nil
}
