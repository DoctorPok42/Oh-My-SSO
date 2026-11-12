// Package health answers "is this server able to serve?" for the orchestrator
// (Docker, a load balancer): /readyz on both servers, and the healthcheck
// command of their images.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	// checkTimeout: a dependency that does not answer in that time is down.
	checkTimeout = 3 * time.Second
	// cacheTTL: /readyz is public, every call must not reach the database.
	cacheTTL = 5 * time.Second
)

// Check is one dependency of the server.
type Check struct {
	Name  string
	Check func(ctx context.Context) error
}

// Handler answers 200 when every check passes, 503 otherwise. It does not
// say which one failed (the endpoint is public): that goes to the log. The
// checks run together, and their result is kept for cacheTTL.
func Handler(checks ...Check) http.Handler {
	var (
		mu     sync.Mutex
		at     time.Time
		failed []string
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if at.IsZero() || time.Since(at) >= cacheTTL {
			failed = run(r.Context(), checks)
			at = time.Now()
			if len(failed) > 0 {
				slog.WarnContext(r.Context(), "not ready", "failed", failed)
			}
		}
		ok := len(failed) == 0
		mu.Unlock()

		status, body := http.StatusOK, `{"status":"ok"}`
		if !ok {
			status, body = http.StatusServiceUnavailable, `{"status":"unavailable"}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

// run returns the names of the checks that failed.
func run(ctx context.Context, checks []Check) []string {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), checkTimeout)
	defer cancel()

	results := make([]error, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.Check(ctx)
		}()
	}
	wg.Wait()

	var failed []string
	for i, err := range results {
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", checks[i].Name, err))
		}
	}
	return failed
}

// Probe is the healthcheck command: it asks url and fails unless it answers
// 200. The images are distroless: there is no curl to do it.
func Probe(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout+2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}
