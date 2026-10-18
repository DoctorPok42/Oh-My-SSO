package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	oidcadapter "sso.internal/sso/internal/adapters/oidc"
)

// mountOIDC plugs the OIDC adapter (Step 10) into the realm routes. The
// adapter routes /oidc/* itself; it only needs to know the realm, which the
// realm middleware already resolved.
//
//	GET /r/{realm}/.well-known/openid-configuration
//	    /r/{realm}/oidc/...
func (s *Server) mountOIDC(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(oidcRealm)
		r.Method(http.MethodGet, "/.well-known/openid-configuration", s.oidc.DiscoveryHandler())
		r.Handle("/oidc/*", s.oidc.Handler())
	})
}

func oidcRealm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		ctx := oidcadapter.WithRealm(r.Context(), oidcadapter.Realm{
			ID:          realm.ID,
			Name:        realm.Name,
			DisplayName: realm.DisplayName,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
