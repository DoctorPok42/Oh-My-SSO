package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	samladapter "sso.internal/sso/internal/adapters/saml"
)

// mountSAML plugs the SAML adapter (Step 11) into the realm routes. The
// adapter routes /saml/* itself; it only needs to know the realm, which the
// realm middleware already resolved.
//
//	/r/{realm}/saml/...
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
