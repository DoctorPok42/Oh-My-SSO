package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/jwks"
)

// jwksMaxAge is how long clients may cache the JWKS (Cache-Control max-age).
//
// Trade-off: longer = fewer requests; shorter = a new key is seen sooner.
// Most client libraries also re-download the JWKS when they meet an unknown
// "kid", so this mainly matters for naive clients. Keep it well below
// service.MinKeyRotationGrace.
const jwksMaxAge = 300 // seconds

// PublicKeySource is the part of core.IdentityCore the JWKS endpoint needs.
// A small interface keeps the handler easy to test with a fake.
type PublicKeySource interface {
	PublicKeys(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) ([]*domain.SigningKey, error)
}

func (s *Server) mountJWKS(r chi.Router) {
	// Same place as the future /r/{realm}/.well-known/openid-configuration
	// (OIDC Discovery §4 puts it under the issuer, and our issuer will be
	// https://<host>/r/{realm}). RFC 8615 defines the /.well-known/ prefix.
	r.Get("/.well-known/jwks.json", s.handleJWKS)
	r.Head("/.well-known/jwks.json", s.handleJWKS)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)

	keys, err := s.publicKeys.PublicKeys(r.Context(), realm.ID, domain.SigningKeyPurposeJWT)
	if err != nil {
		slog.ErrorContext(r.Context(), "jwks: cannot load public keys",
			"realm_id", realm.ID, "error", err)
		w.Header().Set("Cache-Control", "no-store") // never cache an error
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	set, skipped := jwks.FromSigningKeys(keys)
	for _, sk := range skipped {
		// A key we cannot publish is a real incident: tokens it signs will
		// not verify. Log loudly, but still serve the healthy keys.
		slog.ErrorContext(r.Context(), "jwks: signing key left out of the JWKS",
			"realm_id", realm.ID, "kid", sk.Kid, "error", sk.Err)
	}

	body, err := json.Marshal(set)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// ETag = fingerprint of the body. A client that already has this exact
	// JWKS sends it back in If-None-Match and gets a tiny 304 response.
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`

	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(jwksMaxAge))
	h.Set("ETag", etag)
	// Public data: any web origin may read it (browser-based clients).
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("X-Content-Type-Options", "nosniff")

	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // for HEAD, net/http discards the body itself
}

// etagMatches implements the If-None-Match comparison of RFC 9110 §13.1.2:
// a list of entity tags, "*" for any, and weak comparison (W/ ignored).
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}
