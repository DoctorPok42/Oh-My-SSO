// Package logging sets up slog for idp and idp-admin: the format and level
// of the lines (LOG_FORMAT, LOG_LEVEL), and the request ID on every line
// logged with a request's context.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

// Setup makes the default slog logger follow the environment:
//
//	LOG_FORMAT=text   text (default), or json: one object per line
//	LOG_LEVEL=info    debug, info (default), warn or error
//
// The log package (libraries) writes through it too, at the info level. A
// wrong value stops the program: a typo would otherwise hide lines unnoticed.
func Setup() {
	h, err := newHandler(os.Stderr, os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(h))
}

func newHandler(w io.Writer, format, level string) (slog.Handler, error) {
	var opts slog.HandlerOptions
	if level != "" {
		var l slog.Level
		if err := l.UnmarshalText([]byte(level)); err != nil {
			return nil, fmt.Errorf("LOG_LEVEL %q: use debug, info, warn or error", level)
		}
		opts.Level = l
	}
	switch strings.ToLower(format) {
	case "", "text":
		return requestIDHandler{slog.NewTextHandler(w, &opts)}, nil
	case "json":
		return requestIDHandler{slog.NewJSONHandler(w, &opts)}, nil
	}
	return nil, fmt.Errorf("LOG_FORMAT %q: use text or json", format)
}

// requestIDHandler adds request_id to the lines logged with the context of
// a request (slog.InfoContext and the like).
type requestIDHandler struct{ slog.Handler }

func (h requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := middleware.GetReqID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h requestIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return requestIDHandler{h.Handler.WithAttrs(attrs)}
}

func (h requestIDHandler) WithGroup(name string) slog.Handler {
	return requestIDHandler{h.Handler.WithGroup(name)}
}

// Fatal logs msg at the error level and stops the program (exit status 1):
// for a setting the server cannot start with.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// RequestID gives each request an ID (chi's middleware.RequestID), which the
// log lines and the audit entries of the request carry. The X-Request-Id of
// a proxy in front is kept, for correlation, only when it looks like an ID:
// any client can send one, and it would land as is in the logs and the
// audit log.
func RequestID(next http.Handler) http.Handler {
	withID := middleware.RequestID(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get(middleware.RequestIDHeader); id != "" && !validRequestID.MatchString(id) {
			r.Header.Del(middleware.RequestIDHeader)
		}
		withID.ServeHTTP(w, r)
	})
}

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// Recoverer answers 500 when a handler panics, and logs the panic with its
// stack as one error line, request ID included. Not chi's
// middleware.Recoverer: it prints the stack as text on stderr, which a JSON
// log collector cannot read.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p == http.ErrAbortHandler {
				panic(p) // net/http's way to abort a response, not an error
			}
			slog.ErrorContext(r.Context(), "panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			if r.Header.Get("Connection") != "Upgrade" { // a hijacked connection takes no status
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
