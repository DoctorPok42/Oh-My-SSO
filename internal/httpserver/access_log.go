package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"sso.internal/sso/internal/clientip"
)

// accessLog writes one line per request: method, path, status, duration,
// realm and client address; the request ID is added by the log handler
// (internal/logging). The path goes without its query string, which carries
// the OIDC and SAML parameters (the e-mailed links keep their token in the
// fragment, never sent). The probes log at the debug level.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		status := ww.Status()
		if status == 0 { // nothing written: net/http answers 200
			status = http.StatusOK
		}
		level := slog.LevelInfo
		if r.URL.Path == "/health" || r.URL.Path == "/readyz" {
			level = slog.LevelDebug
		}
		slog.LogAttrs(r.Context(), level, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("realm", chi.URLParam(r, "realmName")),
			slog.String("ip", clientip.FromRequest(r)),
		)
	})
}
