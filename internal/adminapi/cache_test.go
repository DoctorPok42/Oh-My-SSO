package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

func TestInfrastructureAnswersTheStatusLines(t *testing.T) {
	s := New(Config{}, Deps{Health: []HealthCheck{
		{Name: "db", Check: func(context.Context) error { return nil }},
		{Name: "smtp", Check: func(context.Context) error { return ErrDisabled }},
	}})
	w := httptest.NewRecorder()
	s.handleInfrastructure(w, httptest.NewRequest(http.MethodGet, "/api/v1/infrastructure", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var got list[healthLine]
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, 2, got.Total)
	require.Equal(t, "healthy", got.Items[0].Status)
	require.Equal(t, "disabled", got.Items[1].Status)
}

// A slow check (the KMS, an SMTP server that hangs) must not hold the
// dashboard: past healthWait the page gets the previous results, the check
// goes on behind it and the next page gets its result.
func TestCachedHealthDoesNotWaitForSlowChecks(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	var calls atomic.Int32
	release := make(chan struct{})
	s := New(Config{Now: clock}, Deps{Health: []HealthCheck{{
		Name: "kms",
		Check: func(context.Context) error {
			if calls.Add(1) == 1 {
				return nil
			}
			<-release
			return errors.New("kms down")
		},
	}}})

	if got := s.cachedHealth(context.Background()); got[0].Status != "healthy" {
		t.Fatalf("first call: %+v, want healthy (nothing to show yet: it waits)", got)
	}
	mu.Lock()
	now = now.Add(healthCacheTTL)
	mu.Unlock()

	start := time.Now()
	got := s.cachedHealth(context.Background())
	if waited := time.Since(start); waited > healthWait+time.Second {
		t.Fatalf("waited %v for a slow check, want about %v", waited, healthWait)
	}
	if got[0].Status != "healthy" {
		t.Fatalf("slow check: %+v, want the previous results", got)
	}
	s.cachedHealth(context.Background()) // the running check is shared, not started again
	if n := calls.Load(); n != 2 {
		t.Fatalf("checks ran %d times, want 2", n)
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for s.cachedHealth(context.Background())[0].Status != "down" {
		if time.Now().After(deadline) {
			t.Fatal("the result of the slow check never reached the next callers")
		}
	}
}
