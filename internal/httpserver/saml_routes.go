package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	samladapter "sso.internal/sso/internal/adapters/saml"
)

func (s *Server) mountSAML(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(samlRealm)
		r.Handle("/saml/*", s.saml.Handler())
	})
}

func samlRealm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		ctx := samladapter.WithRealm(r.Context(), samladapter.Realm{
			ID:          realm.ID,
			Name:        realm.Name,
			DisplayName: realm.DisplayName,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
