package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	oidcadapter "sso.internal/sso/internal/adapters/oidc"
)

func (s *Server) mountOIDC(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(oidcRealm)
		r.Method(http.MethodGet, "/.well-known/openid-configuration", s.oidc.DiscoveryHandler())
		// Called with a client_id, often a secret: rate limited (protocol_limits.go).
		limited := s.limitOIDCClient(s.oidc.Handler())
		for _, p := range []string{"/oidc/token", "/oidc/introspect", "/oidc/revoke"} {
			r.Handle(p, limited)
		}
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
