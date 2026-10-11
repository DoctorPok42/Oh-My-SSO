package service

import "context"

// TimeoutChecker tells whether an admin-issued Timeout currently blocks a
// user (directly or through one of their groups) or the targeted client.
//
// The checker resolves the user's groups itself: callers only pass what they
// know (user + client), they don't have to know which groups to look at.
//
// clientRef may be empty (direct login on the IdP, no client involved yet).
type TimeoutChecker interface {
	HasActiveTimeout(ctx context.Context, userID, clientRef string) (bool, error)
}

// NoActiveTimeouts is the placeholder used until the Timeout feature is
// implemented (Phase 2 of the data model). It never blocks anyone.
//
// Swapping it for the real implementation is a one-line change in main.go.
type NoActiveTimeouts struct{}

func (NoActiveTimeouts) HasActiveTimeout(context.Context, string, string) (bool, error) {
	return false, nil
}
