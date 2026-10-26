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
	Take(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}
