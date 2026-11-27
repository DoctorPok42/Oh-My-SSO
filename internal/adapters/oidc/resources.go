package oidc

import (
	"context"
	"net/http"
	"slices"
)

type resourcesKey struct{}

// readResources keeps the "resource" parameters (RFC 8707) of /authorize and
// /token: the library does not read them. The core checks them.
func readResources(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() == nil && len(r.Form["resource"]) > 0 {
			r = r.WithContext(context.WithValue(r.Context(), resourcesKey{}, slices.Clone(r.Form["resource"])))
		}
		next.ServeHTTP(w, r)
	})
}

// resourcesFrom: the request's resource indicators, nil when none.
func resourcesFrom(ctx context.Context) []string {
	v, _ := ctx.Value(resourcesKey{}).([]string)
	return v
}
