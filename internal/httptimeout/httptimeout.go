// Package httptimeout bounds how long a client may hold a connection of
// cmd/idp and cmd/idp-admin.
//
// ReadHeaderTimeout alone leaves the body and the idle keep-alive time
// unbounded: a client that sends its headers, then one byte of body every
// few seconds (slowloris), keeps a connection and a goroutine forever.
// Every server built here bounds the whole request, the response and the
// idle time between two requests.
//
// A handler that legitimately takes longer (a streamed export, a CSV
// import) calls Extend first, once its caller is authenticated.
package httptimeout

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Timeouts of one http.Server (see http.Server for each field).
type Timeouts struct {
	// ReadHeader: the request line and headers.
	ReadHeader time.Duration
	// Read: the whole request, body included, from its first byte. Once the
	// body is read, it no longer applies.
	Read time.Duration
	// Write: from the end of the headers to the end of the response. A
	// handler still running when it elapses can no longer answer: the client
	// gets a closed connection.
	Write time.Duration
	// Idle: a kept-alive connection waiting for its next request.
	Idle time.Duration
}

var (
	// Public: cmd/idp, on the internet. Its requests are small forms and
	// redirects; a handler (an e-mail, a KMS signature) ends in seconds.
	Public = Timeouts{ReadHeader: 10 * time.Second, Read: 30 * time.Second, Write: 30 * time.Second, Idle: 2 * time.Minute}
	// Admin: cmd/idp-admin, called by the console's server only. The longer
	// calls (exports, CSV imports) call Extend. Bulk actions do not: they run in
	// the background and answer at once.
	Admin = Timeouts{ReadHeader: 10 * time.Second, Read: time.Minute, Write: time.Minute, Idle: 2 * time.Minute}
)

// NewServer is an http.Server with t.
func NewServer(addr string, h http.Handler, t Timeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
	}
}

// Extend gives the current request d, from now, to read its body (a large
// upload) and to write its response. Call it before reading the body. Only
// for authenticated callers: a slow anonymous client is what the server
// timeouts protect against.
func Extend(w http.ResponseWriter, r *http.Request, d time.Duration) {
	rc := http.NewResponseController(w)
	until := time.Now().Add(d)
	for _, set := range []func(time.Time) error{rc.SetReadDeadline, rc.SetWriteDeadline} {
		// ErrNotSupported: a test recorder, there is no connection.
		if err := set(until); err != nil && !errors.Is(err, http.ErrNotSupported) {
			slog.WarnContext(r.Context(), "http: cannot extend the request deadlines", "path", r.URL.Path, "error", err)
			return
		}
	}
}
