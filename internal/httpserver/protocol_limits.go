package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	"sso.internal/sso/internal/ratelimit"
)

// Rate limits of the protocol endpoints that an application calls with its
// client_id (OIDC /token, /introspect, /revoke) or that a browser reaches
// with a SAML message, before any session of ours exists.

const (
	routeOIDCClient = "oidc.client"
	routeSAML       = "saml"

	// maxOIDCClientBody: a token, introspection or revocation request is a
	// form of a few kilobytes (a code and its verifier, a token).
	maxOIDCClientBody = 64 << 10
)

// RateRule: at most Max hits per sliding Window.
type RateRule struct {
	Max    int64
	Window time.Duration
}

func (r RateRule) String() string { return strconv.FormatInt(r.Max, 10) + "/" + r.Window.String() }

// ProtocolLimits are the rate limits of the protocol endpoints. Every
// request is counted before it runs (a burst of parallel requests cannot
// pass all at once); a request whose client proves its secret gives its
// hits back.
type ProtocolLimits struct {
	// OIDCPerIP: requests to /token, /introspect and /revoke from one address
	// that authenticate no client: a wrong or unknown secret, or none (a
	// public client). The servers of the applications, which make most of
	// these calls with their secret (a resource server introspecting every
	// request, many backends behind one NAT address), are never slowed down.
	OIDCPerIP RateRule
	// ClientFailuresPerIP: failed authentications of one client_id from one
	// address. While it is reached, the right secret is refused from there
	// too (or the refusal would tell which secret is right). Only requests
	// that send a secret are checked: a public client sending its client_id
	// alone is never refused by it. There is no limit per client_id alone:
	// the client_id is public, anyone could lock its application out.
	ClientFailuresPerIP RateRule
	// SAMLPerIP: every request to /saml/sso, /login, /consent and /slo from
	// one address: each one parses XML, most check a signature. A sign-in
	// takes three of them.
	SAMLPerIP RateRule
}

// DefaultProtocolLimits apply without configuration (cmd/idp reads the
// RATE_LIMIT_* variables, see app.ProtocolRateLimits).
var DefaultProtocolLimits = ProtocolLimits{
	OIDCPerIP:           RateRule{Max: 600, Window: time.Minute},
	ClientFailuresPerIP: RateRule{Max: 10, Window: 15 * time.Minute},
	SAMLPerIP:           RateRule{Max: 300, Window: time.Minute},
}

// WithProtocolLimits replaces DefaultProtocolLimits.
func WithProtocolLimits(l ProtocolLimits) Option {
	return func(s *Server) { s.protocolLimits = l }
}

func (r RateRule) on(key string) ratelimit.Rule {
	return ratelimit.Rule{Key: key, Limit: r.Max, Window: r.Window}
}

// limitOIDCClient guards /token, /introspect and /revoke: it counts the
// request under its address and, when it sends a secret, under its
// client_id and address; the OIDC adapter reports a client that proved its
// secret, and these hits are given back. A refusal is 429 with Retry-After.
func (s *Server) limitOIDCClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions { // CORS preflight: no credentials, nothing to count
			next.ServeHTTP(w, r)
			return
		}
		realm := realmFromContext(r)
		ip := clientIP(r)
		l := s.protocolLimits

		r.Body = http.MaxBytesReader(w, r.Body, maxOIDCClientBody)
		clientID, withSecret, err := requestClient(r)
		if err != nil {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "the request body is not a valid form")
			return
		}

		rules := []ratelimit.Rule{l.OIDCPerIP.on(ratelimit.Key(routeOIDCClient, realm.ID, "ip", ip))}
		if withSecret && clientID != "" {
			rules = append(rules, l.ClientFailuresPerIP.on(clientFailureKey(realm.ID, clientID, ip)))
		}
		res, err := s.rateLimiter.Reserve(r.Context(), rules...)
		if err != nil {
			slog.ErrorContext(r.Context(), "oidc: rate limit", "error", err)
			writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "")
			return
		}
		if !res.OK {
			writeOAuthTooManyRequests(w, r, res.RetryAfter)
			return
		}

		var once sync.Once
		ctx := oidcadapter.WithClientAuthenticated(r.Context(), func(string) {
			once.Do(func() {
				// The answer does not depend on it: hits that cannot be given
				// back are logged, not turned into an error.
				ctx := context.WithoutCancel(r.Context())
				if err := s.rateLimiter.Release(ctx, res.Hits...); err != nil {
					slog.ErrorContext(ctx, "oidc: rate limit: give back the hits of an authenticated client", "error", err)
				}
			})
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestClient: the client_id the request claims and whether it sends a
// secret, as the OIDC library reads them (HTTP Basic, form-encoded per RFC
// 6749 2.3.1, else client_id and client_secret in the form). It parses the
// form: the library reuses it.
func requestClient(r *http.Request) (clientID string, withSecret bool, err error) {
	if user, _, ok := r.BasicAuth(); ok {
		if id, err := url.QueryUnescape(user); err == nil {
			return id, true, nil
		}
		return user, true, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", false, err
	}
	return r.Form.Get("client_id"), r.Form.Get("client_secret") != "", nil
}

// clientFailureKey: per client_id and address. The client_id comes from the
// request: a long one is hashed, so a key stays small whatever is sent.
func clientFailureKey(realmID, clientID, ip string) string {
	if len(clientID) > 128 {
		sum := sha256.Sum256([]byte(clientID))
		clientID = "sha256:" + hex.EncodeToString(sum[:])
	}
	return ratelimit.Key(routeOIDCClient, realmID, "client_failures_ip", clientID+"|"+ip)
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// writeOAuthError: an error of the OAuth endpoints (RFC 6749 5.2), written
// before the OIDC library, so with the CORS headers it would have set: any
// origin, no credentials (adapters/oidc). Without them, a browser
// application would only see a network error.
func writeOAuthError(w http.ResponseWriter, r *http.Request, status int, code, description string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if r.Header.Get("Origin") != "" {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "Retry-After")
	}
	writeJSON(w, status, oauthError{Error: code, Description: description})
}

// writeOAuthTooManyRequests: 429, and when to try again.
func writeOAuthTooManyRequests(w http.ResponseWriter, r *http.Request, retry time.Duration) {
	secs := ratelimit.RetryAfterSeconds(retry)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeOAuthError(w, r, http.StatusTooManyRequests, "rate_limited",
		"too many requests, retry in "+strconv.Itoa(secs)+" seconds")
}

// limitSAML guards the SAML endpoints that parse a message or show a page.
// A refusal is the 429 page of the SAML adapter, with Retry-After.
func (s *Server) limitSAML(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		key := ratelimit.Key(routeSAML, realm.ID, "ip", clientIP(r))
		res, err := s.rateLimiter.Reserve(r.Context(), s.protocolLimits.SAMLPerIP.on(key))
		if err != nil {
			slog.ErrorContext(r.Context(), "saml: rate limit", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !res.OK {
			w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(res.RetryAfter)))
			s.saml.RenderTooManyRequests(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
