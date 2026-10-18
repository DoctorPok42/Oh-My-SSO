package oidc

import "context"

// Realm is what the adapter needs to know about the realm of a request. The
// HTTP server resolves it from /r/{realm} and puts it in the context with
// WithRealm before calling the adapter's handlers.
type Realm struct {
	ID          string
	Name        string
	DisplayName string
}

type realmKey struct{}

// WithRealm returns a context that carries the realm of the request.
func WithRealm(ctx context.Context, r Realm) context.Context {
	return context.WithValue(ctx, realmKey{}, r)
}

func realmFrom(ctx context.Context) (Realm, bool) {
	r, ok := ctx.Value(realmKey{}).(Realm)
	return r, ok && r.ID != "" && r.Name != ""
}
