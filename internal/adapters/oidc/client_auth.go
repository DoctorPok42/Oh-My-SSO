package oidc

import "context"

type clientAuthenticatedKey struct{}

// WithClientAuthenticated: done is called with the client_id when a request
// made with ctx authenticates its client by secret (/token, /introspect,
// /revoke): a known client_id and its right secret. The caller (the HTTP
// server's rate limit, which counted the request in advance) then gives
// back what it counted.
func WithClientAuthenticated(ctx context.Context, done func(clientID string)) context.Context {
	return context.WithValue(ctx, clientAuthenticatedKey{}, done)
}

// ReportClientAuthenticated tells the done of WithClientAuthenticated, if any.
func ReportClientAuthenticated(ctx context.Context, clientID string) {
	if done, ok := ctx.Value(clientAuthenticatedKey{}).(func(string)); ok {
		done(clientID)
	}
}
