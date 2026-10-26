package httpserver

import (
	"mime"
	"net/http"
)

// requireJSON refuses state-changing requests that are not JSON. Together
// with the SameSite=Lax session cookie, it stops a malicious web page from
// submitting a plain HTML form to these endpoints (CSRF): a browser cannot
// send "Content-Type: application/json" cross-site without a CORS preflight,
// which we never approve.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "json_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
