package ratelimit

import (
	"context"
	"math"
	"time"
)

// Rule: at most Limit hits of Key per sliding Window.
type Rule struct {
	Key    string
	Limit  int64
	Window time.Duration
}

// Hit is one hit counted under Key by Reserve. Member tells it from the
// others of the key, so that Release removes this one only.
type Hit struct {
	Key    string
	Member string
}

// Reservation is the outcome of Reserve.
type Reservation struct {
	// OK: every rule had room. Hits holds the hit counted under each.
	OK   bool
	Hits []Hit
	// RetryAfter, when refused: how long until every refusing rule has room.
	RetryAfter time.Duration
}

// Limiter: a sliding window of hits per key (Valkey, shared by every
// instance).
type Limiter interface {
	// Allow checks key and, when allowed, counts this hit.
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error)
	// Reserve counts one hit under every rule, all or none: when one rule has
	// no room, the hits counted under the others are removed. Checking and
	// counting a key is one atomic step: concurrent requests cannot all pass
	// the check before any of them is counted.
	Reserve(ctx context.Context, rules ...Rule) (Reservation, error)
	// Release removes hits counted by Reserve: an attempt that turned out to
	// be legitimate (a client that proved its secret) gives its hits back.
	Release(ctx context.Context, hits ...Hit) error
}

func Key(route, realmID, scope, value string) string {
	return route + ":" + realmID + ":" + scope + ":" + value
}

// RetryAfterSeconds is d for a Retry-After header: whole seconds, at least 1.
func RetryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}
