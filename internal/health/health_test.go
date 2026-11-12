package health_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/health"
)

func get(h http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec
}

func TestHandler(t *testing.T) {
	up := health.Check{Name: "up", Check: func(context.Context) error { return nil }}
	down := health.Check{Name: "db", Check: func(context.Context) error { return errors.New("password for sso is wrong") }}

	t.Run("every check passes", func(t *testing.T) {
		rec := get(health.Handler(up, up))
		require.Equal(t, http.StatusOK, rec.Code)
		require.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	})

	t.Run("no check", func(t *testing.T) {
		require.Equal(t, http.StatusOK, get(health.Handler()).Code)
	})

	t.Run("one fails: 503, and the reason stays out of the answer", func(t *testing.T) {
		rec := get(health.Handler(up, down))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.JSONEq(t, `{"status":"unavailable"}`, rec.Body.String())
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	})

	t.Run("a check that does not answer is down", func(t *testing.T) {
		hang := health.Check{Name: "valkey", Check: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}}
		start := time.Now()
		rec := get(health.Handler(hang))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Less(t, time.Since(start), 10*time.Second)
	})

	t.Run("the result is kept for a few seconds", func(t *testing.T) {
		var calls atomic.Int32
		counted := health.Check{Name: "db", Check: func(context.Context) error { calls.Add(1); return nil }}
		h := health.Handler(counted)
		for range 5 {
			get(h)
		}
		require.EqualValues(t, 1, calls.Load())
	})
}

func TestProbe(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()

	require.NoError(t, health.Probe(context.Background(), srv.URL))
	status = http.StatusServiceUnavailable
	require.Error(t, health.Probe(context.Background(), srv.URL))
	srv.Close()
	require.Error(t, health.Probe(context.Background(), srv.URL), "nothing listens")
}
