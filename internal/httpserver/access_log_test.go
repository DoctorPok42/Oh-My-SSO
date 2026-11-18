package httpserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/metrics/metricstest"
)

func TestAccessLogFeedsTheMetrics(t *testing.T) {
	s := New(nil, nil, nil, &fakeRealmByName{realm: &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}}, nil, nil)
	health := map[string]string{"method": "GET", "route": "/health", "code": "200"}
	before := metricstest.Value(t, "omsso_http_request_duration_seconds", health)

	s.Router().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))

	require.Equal(t, before+1, metricstest.Value(t, "omsso_http_request_duration_seconds", health))
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	realm := &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}
	s := New(nil, nil, nil, &fakeRealmByName{realm: realm}, nil, nil)
	serve := func(target string) map[string]any {
		buf.Reset()
		s.Router().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
		for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var line map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &line), raw)
			if line["msg"] == "request" {
				return line
			}
		}
		t.Fatalf("no access log line for %s in %q", target, buf.String())
		return nil
	}

	line := serve("/r/acme/nothing-here?code=secret-code")
	require.Equal(t, "INFO", line["level"])
	require.Equal(t, "GET", line["method"])
	require.Equal(t, "/r/acme/nothing-here", line["path"])
	require.Equal(t, "acme", line["realm"])
	require.EqualValues(t, http.StatusNotFound, line["status"])
	require.Equal(t, "192.0.2.1", line["ip"])
	require.Contains(t, line, "duration_ms")
	require.NotContains(t, buf.String(), "secret-code")

	line = serve("/health")
	require.Equal(t, "DEBUG", line["level"]) // probes do not flood the log
	require.EqualValues(t, http.StatusOK, line["status"])
	require.Equal(t, "", line["realm"])
}
