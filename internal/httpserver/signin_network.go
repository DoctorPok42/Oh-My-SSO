package httpserver

import (
	"context"
	"log/slog"
	"net/http"
)

// SignInNetworks decides whether an address may sign in to a realm (the
// realm's IP allowlist, implemented by service.SignInNetworkService).
type SignInNetworks interface {
	Allows(ctx context.Context, realmID, ip string) (bool, error)
}

// WithSignInNetworks applies the IP allowlist of each realm to sign-in
// (password, passkey without password). Without it, nothing is filtered.
func WithSignInNetworks(n SignInNetworks) Option {
	return func(s *Server) { s.networks = n }
}

// requireSignInNetwork refuses a sign-in from an address outside the realm's
// IP allowlist with 403 "network_not_allowed", before anything else: no
// password is checked, nothing counts towards the rate limits or the lockout
// of the account. When the list cannot be read, the sign-in is refused (500):
// an unreadable list must not open the realm.
func (s *Server) requireSignInNetwork(next http.Handler) http.Handler {
	if s.networks == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		ok, err := s.networks.Allows(r.Context(), realm.ID, clientIP(r))
		if err != nil {
			slog.ErrorContext(r.Context(), "sign-in: cannot read the IP allowlist", "realm_id", realm.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, "network_not_allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}
