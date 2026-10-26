package adminapi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The dashboard's infrastructure checks are expensive (a signature by the
// KMS, an HTTP call, an SMTP connection): at most once per healthCacheTTL.
func TestCachedHealthRunsChecksOncePerTTL(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	s := New(Config{Now: func() time.Time { return now }}, Deps{Health: []HealthCheck{{
		Name: "db",
		Check: func(ctx context.Context) error {
			calls.Add(1)
			return ctx.Err() // a cancelled caller must not poison the cache
		},
	}}})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	first := s.cachedHealth(cancelled)
	if len(first) != 1 || first[0].Status != "healthy" {
		t.Fatalf("first check: %+v, want healthy (checks ignore the caller's cancellation)", first)
	}
	s.cachedHealth(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("checks ran %d times within the TTL, want 1", got)
	}

	now = now.Add(healthCacheTTL)
	s.cachedHealth(context.Background())
	if got := calls.Load(); got != 2 {
		t.Fatalf("checks ran %d times after the TTL, want 2", got)
	}
}
