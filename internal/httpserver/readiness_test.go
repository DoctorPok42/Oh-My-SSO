package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/health"
)

func TestReadyz(t *testing.T) {
	get := func(s *Server) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec
	}
	down := health.Check{Name: "Valkey", Check: func(context.Context) error { return errors.New("connection refused") }}

	require.Equal(t, http.StatusOK, get(newLoginGuardServer(&denyingLimiter{})).Code, "no check configured")
	require.Equal(t, http.StatusServiceUnavailable, get(newLoginGuardServer(&denyingLimiter{}, WithReadiness(down))).Code)

	rec := httptest.NewRecorder()
	newLoginGuardServer(&denyingLimiter{}).Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rec.Code, "/health only says the process runs")
}
