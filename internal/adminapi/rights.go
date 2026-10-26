package adminapi

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"
)


type RightsEpoch interface {
	// LastChange is the time of the last change. Unknown (first start, data
	// lost): the implementation answers "now", the safe value.
	LastChange(ctx context.Context) (time.Time, error)
	// Changed records a change at t. The time never moves backwards.
	Changed(ctx context.Context, t time.Time) error
}

// memoryEpoch: the RightsEpoch of a single process (tests, or Deps.Rights
// left nil). It starts at the creation of the server: tokens issued before
// it started are never trusted.
type memoryEpoch struct {
	mu sync.Mutex
	at time.Time
}

func (e *memoryEpoch) LastChange(context.Context) (time.Time, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.at, nil
}

func (e *memoryEpoch) Changed(_ context.Context, t time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t.After(e.at) {
		e.at = t
	}
	return nil
}

// tokenRights returns the permissions of a token that may be trusted, or
// ok=false when they must be checked against the database.
func (s *Server) tokenRights(ctx context.Context, c *accessClaims) (rights []string, ok bool) {
	if c.Entitlements == nil {
		return nil, false
	}
	issued, known := unix(c.IssuedAt)
	if !known {
		return nil, false
	}
	last, err := s.d.Rights.LastChange(ctx)
	if err != nil {
		// Valkey unreachable: the database decides (slower, never wrong).
		slog.WarnContext(ctx, "admin api: rights epoch unavailable, checking permissions in the database", "error", err)
		return nil, false
	}
	if !issued.After(last.Add(clockSkew)) {
		return nil, false
	}
	return c.Entitlements, true
}

// may: the trusted token grants this permission.
func (a *adminContext) may(resource, action string) bool {
	return a.rightsFromToken && slices.Contains(a.rights, resource+":"+action)
}

// recordRightsChange wraps every change of the master realm (any route
// under /realms/master that is not a read): the epoch moves before the
// change (a token issued while it runs is not trusted) and after it (the
// change is visible from then on). If the time of the change cannot be
// recorded, the change is refused: other admins' tokens could otherwise
// keep a permission they just lost.
func (s *Server) recordRightsChange(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, realm := adminFrom(r), realmFrom(r)
		if realm == nil || realm.ID != a.master.ID {
			next.ServeHTTP(w, r)
			return
		}
		if err := s.d.Rights.Changed(r.Context(), s.now()); err != nil {
			slog.ErrorContext(r.Context(), "admin api: cannot record a change of the master realm", "error", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable",
				"changes to the master realm are paused: Valkey is unreachable")
			return
		}
		defer func() {
			// Detached: the change happened even if the console hung up.
			if err := s.d.Rights.Changed(context.WithoutCancel(r.Context()), s.now()); err != nil {
				slog.ErrorContext(r.Context(), "admin api: cannot record the end of a change of the master realm", "error", err)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// effectivePermissionNames: what /me shows, from the token when it may be
// trusted, from the RBAC service otherwise.
func (s *Server) effectivePermissionNames(ctx context.Context, a *adminContext) (map[string]bool, error) {
	if a.rightsFromToken {
		held := make(map[string]bool, len(a.rights))
		for _, p := range a.rights {
			held[p] = true
		}
		return held, nil
	}
	effective, err := s.d.RBAC.GetEffectivePermissions(ctx, a.user.ID, a.client.ID)
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool, len(effective))
	for _, p := range effective {
		held[p.Resource+":"+p.Action] = true
	}
	return held, nil
}
