package httpserver

import (
	_ "embed"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Development-only pages (APP_ENV=development, see cmd/idp/main.go).
//
// The real login pages and account console come later (Go templates +
// HTMX, Step 14). Until then this page lets you try the MFA flows by hand
// with a real authenticator app on your phone. It only calls the public
// JSON API: no shortcut, no hidden endpoint.

//go:embed devpages/mfa.html
var devMFAPage []byte

func (s *Server) mountDevPages(r chi.Router) {
	r.Get("/dev/mfa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write(devMFAPage)
	})
}
