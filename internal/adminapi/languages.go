package adminapi

import (
	"context"
	"net/http"
	"strings"

	"sso.internal/sso/internal/i18n"
)

// The Admin API answers in the language of the console that calls it: the
// console (admin/src/lib/api.ts) sends its Accept-Language. The error
// sentences that the services produce are translated here, once, when the
// answer is written (writeServiceError).

type bundleKey struct{}

// languages puts the request's language preferences and the catalogue of
// the server in its context.
func (s *Server) languages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), bundleKey{}, s.cfg.Languages)
		var hints []string
		for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
			if tag, _, _ := strings.Cut(strings.TrimSpace(part), ";"); tag != "" {
				hints = append(hints, tag)
			}
		}
		ctx = i18n.WithHints(ctx, hints)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// localizer is the language of a request (English when the server has no
// catalogue in its context, as in some tests).
func localizer(ctx context.Context) *i18n.Localizer {
	b, _ := ctx.Value(bundleKey{}).(*i18n.Bundle)
	if b == nil {
		b = i18n.MustDefault()
	}
	return b.For(ctx)
}
