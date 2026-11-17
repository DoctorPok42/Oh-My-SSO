package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"
)

func TestNewHandlerSettings(t *testing.T) {
	for _, ok := range [][2]string{{"", ""}, {"text", "debug"}, {"JSON", "WARN"}, {"json", "error"}} {
		_, err := newHandler(&bytes.Buffer{}, ok[0], ok[1])
		require.NoError(t, err, ok)
	}
	for _, bad := range [][2]string{{"logfmt", ""}, {"", "verbose"}} {
		_, err := newHandler(&bytes.Buffer{}, bad[0], bad[1])
		require.Error(t, err, bad)
	}
}

func TestLevelFiltersLines(t *testing.T) {
	var buf bytes.Buffer
	h, err := newHandler(&buf, "json", "warn")
	require.NoError(t, err)
	l := slog.New(h)
	l.Info("hidden")
	l.Warn("shown")
	require.NotContains(t, buf.String(), "hidden")
	require.Contains(t, buf.String(), "shown")
}

func TestRequestIDOnLinesWithARequestContext(t *testing.T) {
	var buf bytes.Buffer
	h, err := newHandler(&buf, "json", "")
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "abc-1")

	slog.New(h).With("realm", "acme").InfoContext(ctx, "with")
	var line map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line))
	require.Equal(t, "abc-1", line["request_id"])
	require.Equal(t, "acme", line["realm"])

	buf.Reset()
	slog.New(h).Info("without")
	require.NotContains(t, buf.String(), "request_id")
}

func TestRecovererLogsThePanicAsOneLine(t *testing.T) {
	var buf bytes.Buffer
	h, err := newHandler(&buf, "json", "")
	require.NoError(t, err)
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	handler := RequestID(Recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var line map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line), "one JSON object, stack included: %s", buf.String())
	require.Equal(t, "ERROR", line["level"])
	require.Equal(t, "boom", line["panic"])
	require.NotEmpty(t, line["request_id"])
	require.Contains(t, line["stack"], "logging_test.go")
}

func TestRecovererLetsAnAbortThrough(t *testing.T) {
	h := Recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	require.PanicsWithValue(t, http.ErrAbortHandler, func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
}

func TestRequestIDKeepsOnlyAnIDLikeHeader(t *testing.T) {
	var got string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = middleware.GetReqID(r.Context())
	}))
	serve := func(header string) string {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			r.Header.Set(middleware.RequestIDHeader, header)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return got
	}

	require.Equal(t, "7f3c2a9e-1b4d-4e8f-9a6b-2c5d8e1f0a3b", serve("7f3c2a9e-1b4d-4e8f-9a6b-2c5d8e1f0a3b"))
	require.NotEmpty(t, serve(""))
	for _, bad := range []string{"a b", "x\"y", string(bytes.Repeat([]byte("a"), 65))} {
		id := serve(bad)
		require.NotEmpty(t, id)
		require.NotEqual(t, bad, id)
	}
}
