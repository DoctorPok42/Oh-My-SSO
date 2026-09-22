package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type realmContextKey struct{}

func (s *Server) realmMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "realmName")

		realm, err := s.realms.GetByName(r.Context(), name)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				writeError(w, http.StatusNotFound, "realm_not_found")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}

		if realm.Status != domain.RealmActive {
			writeError(w, http.StatusNotFound, "realm_not_found")
			return
		}

		ctx := context.WithValue(r.Context(), realmContextKey{}, realm)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func realmFromContext(r *http.Request) *domain.Realm {
	realm, _ := r.Context().Value(realmContextKey{}).(*domain.Realm)
	return realm
}
