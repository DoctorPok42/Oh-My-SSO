package httpserver

import (
	_ "embed"
	"net/http"

	"github.com/go-chi/chi/v5"
)


var devMFAPage []byte

func (s *Server) mountDevPages(r chi.Router) {
	r.Get("/dev/mfa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write(devMFAPage)
	})
}
