// Package oidcstore holds the short-lived state of OIDC logins (Step 10):
// an authorization request lives from /authorize until the code exchange,
// ten minutes at most, and an authorization code one minute.
//
// Like internal/mfastore, everything here can be lost without harm (the user
// just starts the login again), which is why it lives in Valkey rather than
// in Postgres. The OIDC adapter only stores hashes of the random values it
// hands out (codes, browser binding), never the values themselves.
//
// The interface is a tiny key/value API on purpose: the adapter owns the
// meaning of each key, this package only guarantees expiry and atomicity.
package oidcstore

import (
	"context"
	"time"
)

// Store is implemented by Valkey (production) and Memory (tests).
type Store interface {
	// Put stores value under key for ttl, replacing any previous value.
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// PutIfAbsent stores value only if key does not exist yet, and reports
	// whether it did. Of two concurrent calls, exactly one gets true.
	PutIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// Get returns (nil, nil) when the key does not exist or has expired.
	Get(ctx context.Context, key string) ([]byte, error)
	// Take returns the value and deletes it in one atomic step ((nil, nil)
	// when absent): of two concurrent calls, only one gets the value. This
	// is what makes an authorization code single-use.
	Take(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}
