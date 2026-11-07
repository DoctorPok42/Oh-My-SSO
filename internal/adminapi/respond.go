package adminapi

import (
	"sso.internal/sso/internal/i18n"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// JSON in, JSON out. Errors always have the same shape:
//
//	{"error": "<stable code>", "message": "<sentence>", "field": "<input field>"}
//
// The codes are what the admin console switches on (step_up_required,
// last_admin, managed_by_config...); the message can be shown as is.

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Field   string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // admin data never goes to a cache
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErrorT answers an error whose sentence is translated: the console's
// language (see languages.go).
func writeErrorT(w http.ResponseWriter, r *http.Request, status int, code string, t i18n.Text) {
	writeJSON(w, status, errorBody{Error: code, Message: localizer(r.Context()).Text(t)})
}

// writeServiceError maps the admin service's errors to HTTP. Anything that
// is not an *AdminError is a server problem: logged, never shown.
func writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *service.AdminError
	if errors.As(err, &ae) {
		status := http.StatusBadRequest
		switch ae.Kind {
		case service.AdminNotFound:
			status = http.StatusNotFound
		case service.AdminConflict, service.AdminRefused:
			status = http.StatusConflict
		}
		message := ae.Message
		if ae.Text.Key != "" {
			message = localizer(r.Context()).Text(ae.Text)
		}
		writeJSON(w, status, errorBody{Error: ae.Code, Message: message, Field: ae.Field})
		return
	}
	slog.ErrorContext(r.Context(), "admin api: internal error", "method", r.Method, "path", r.URL.Path, "error", err)
	writeErrorT(w, r, http.StatusInternalServerError, "internal_error", i18n.M("admin.error.internal", "something went wrong on the server, see its logs"))
}

// maxBodyBytes: admin forms are small; a SAML metadata file is the biggest.
const maxBodyBytes = 256 << 10

// decode reads a JSON body. Unknown fields are refused: a typo like
// "requireConsent" must not be silently ignored.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	return decodeUpTo(w, r, dst, maxBodyBytes)
}

// decodeUpTo is decode for the one body that is not a small form.
func decodeUpTo(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		writeErrorT(w, r, http.StatusBadRequest, "invalid_json", i18n.M("admin.error.invalid_json", "the request body is not valid JSON for this endpoint: {error}", "error", err.Error()))
		return false
	}
	return true
}

// requireJSON: state-changing requests must be JSON (defence in depth; the
// API is only called server to server by the admin console).
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if r.ContentLength != 0 && (err != nil || mt != "application/json") {
				writeErrorT(w, r, http.StatusUnsupportedMediaType, "json_required", i18n.M("admin.error.json_required", "send Content-Type: application/json"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// list is the shape of every paginated answer.
type list[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

const (
	defaultLimit = 50
	maxLimit     = 200
)

func page(r *http.Request) repository.Page {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return repository.Page{Offset: offset, Limit: limit}
}

func items[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// timeParam reads an RFC 3339 time or a date (YYYY-MM-DD, UTC midnight).
func timeParam(r *http.Request, name string) (time.Time, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, true
	}
	return time.Time{}, false
}
