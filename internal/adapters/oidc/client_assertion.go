package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/core/domain"
)

// Client authentication with private_key_jwt (RFC 7523, OIDC Core section
// 9): the client signs a short-lived JWT with its own key, and the IdP checks
// it with the public keys registered for the client (jwks) or published by it
// (jwks_uri). No secret is shared.

const (
	// assertionMaxLifetime: an assertion must expire within the hour (the
	// library accepts an "iat" up to an hour old): its jti is remembered
	// until then.
	assertionMaxLifetime = time.Hour
	assertionClockSkew   = time.Second // as the library's own verifier

	jwksCacheTTL     = 5 * time.Minute
	jwksRefetchAfter = time.Minute // an unknown kid fetches again at most this often
	jwksFetchTimeout = 5 * time.Second
	jwksMaxBytes     = 64 << 10
	minClientRSABits = 2048
)

type assertedClientKey struct{}

// assertedClientFrom: the client_id a client_assertion of this request proved.
func assertedClientFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(assertedClientKey{}).(string)
	return id, ok
}

// clientAssertion verifies a client_assertion on /token, /introspect and
// /revoke before the library: the library neither checks that an assertion
// is used once nor reads one for the client_credentials grant. The client it
// proves goes in the context. The library still checks the assertion again
// on its own paths (code, refresh, introspection, revocation).
func (a *Adapter) clientAssertion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The library reads r.Form too: same parameters, query included.
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("client_assertion") == "" {
			next.ServeHTTP(w, r)
			return
		}
		if _, _, basic := r.BasicAuth(); basic || r.Form.Get("client_secret") != "" {
			op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("use one client authentication method only"), a.logger)
			return
		}
		clientID, err := a.verifyClientAssertion(r.Context(), r.Form)
		if err != nil {
			op.RequestError(w, r, err, a.logger)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), assertedClientKey{}, clientID)))
	})
}

// verifyClientAssertion checks signature, issuer = subject = a private_key_jwt
// client, audience = our issuer, expiry (op.VerifyJWTAssertion), then that
// the jti was never seen (OIDC Core section 9: used once).
func (a *Adapter) verifyClientAssertion(ctx context.Context, form url.Values) (string, error) {
	if form.Get("client_assertion_type") != oidc.ClientAssertionTypeJWTAssertion {
		return "", oidc.ErrInvalidRequest().WithDescription("client_assertion_type must be " + oidc.ClientAssertionTypeJWTAssertion)
	}
	realm, err := a.storage.realm(ctx)
	if err != nil {
		return "", err
	}
	v := op.NewJWTProfileVerifier(a.storage, a.issuer(realm.Name), assertionMaxLifetime, assertionClockSkew)
	req, err := op.VerifyJWTAssertion(ctx, form.Get("client_assertion"), v)
	if err != nil {
		return "", oidc.ErrInvalidClient().WithDescription("invalid client_assertion").WithParent(err)
	}
	if id := form.Get("client_id"); id != "" && id != req.Issuer {
		return "", oidc.ErrInvalidClient().WithDescription("client_id does not match the client_assertion")
	}
	left := req.ExpiresAt.AsTime().Sub(a.now())
	if req.JWTID == "" || left > assertionMaxLifetime {
		return "", oidc.ErrInvalidClient().WithDescription("the client_assertion needs a jti and must expire within the hour")
	}
	first, err := a.store.PutIfAbsent(ctx, assertionKey(realm.ID, req.Issuer, req.JWTID), []byte{1}, left+time.Minute)
	if err != nil {
		return "", oidc.ErrServerError().WithParent(err)
	}
	if !first {
		return "", oidc.ErrInvalidClient().WithDescription("this client_assertion was already used")
	}
	ReportClientAuthenticated(ctx, req.Issuer)
	return req.Issuer, nil
}

// assertionKey: a used jti, per realm and client, hashed (bounded size).
func assertionKey(realmID, clientID, jti string) string {
	return "oidc:jti:" + sha256Hex(realmID+"\x00"+clientID+"\x00"+jti)
}

// clientKeys finds the public key a private_key_jwt client signed with.
type clientKeys struct {
	http   *http.Client
	now    func() time.Time
	logger *slog.Logger

	mu    sync.Mutex
	cache map[string]fetchedJWKS // by jwks_uri
}

// fetchedJWKS: the last JWK set read from a jwks_uri (nil if none yet), when,
// and the last attempt to read it, failed or not.
type fetchedJWKS struct {
	set   *jose.JSONWebKeySet
	at    time.Time
	tried time.Time
	err   error // of the last attempt
}

func newClientKeys(now func() time.Time, logger *slog.Logger) *clientKeys {
	return &clientKeys{http: newKeysHTTPClient(), now: now, logger: logger, cache: map[string]fetchedJWKS{}}
}

func (k *clientKeys) key(ctx context.Context, app *domain.ClientApp, kid string) (*jose.JSONWebKey, error) {
	if app.JWKSURI == "" {
		var set jose.JSONWebKeySet
		if err := json.Unmarshal([]byte(app.JWKS), &set); err != nil {
			return nil, fmt.Errorf("client %q: stored jwks: %w", app.ClientID, err)
		}
		return pickKey(&set, kid)
	}
	f, err := k.fetch(ctx, app.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	key, err := pickKey(f.set, kid)
	if err != nil {
		// An unknown kid: the client may have rotated its keys (fetch reads
		// again at most once a minute).
		if f, ferr := k.fetch(ctx, app.JWKSURI, true); ferr == nil {
			return pickKey(f.set, kid)
		}
	}
	return key, err
}

// fetch returns the JWK set of uri, read again once it is jwksCacheTTL old,
// or now when force (an unknown kid). Whatever happens, uri is read at most
// once per jwksRefetchAfter: a failed read keeps the keys already known (a
// client is not cut off by an outage of its key server), and a request never
// waits for a read that just failed.
func (k *clientKeys) fetch(ctx context.Context, uri string, force bool) (fetchedJWKS, error) {
	k.mu.Lock()
	f, ok := k.cache[uri]
	k.mu.Unlock()
	now := k.now()
	if ok && ((f.set != nil && !force && now.Sub(f.at) < jwksCacheTTL) || now.Sub(f.tried) < jwksRefetchAfter) {
		return f.result()
	}
	set, err := k.download(ctx, uri)
	// Merged into the entry as it is now: another read may have ended
	// meanwhile, and a failure must not bring back the keys it replaced.
	k.mu.Lock()
	cur := k.cache[uri]
	if err == nil && !now.Before(cur.at) {
		cur.set, cur.at = set, now
	}
	if !now.Before(cur.tried) {
		cur.tried, cur.err = now, err
	}
	k.cache[uri] = cur
	k.mu.Unlock()
	if err != nil {
		host := ""
		if u, perr := url.Parse(uri); perr == nil {
			host = u.Host // not the whole URL: it may hold a token
		}
		k.logger.WarnContext(ctx, "oidc: cannot read a client's jwks_uri, its known keys are kept",
			"host", host, "known_keys", cur.set != nil, "error", err)
	}
	return cur.result()
}

// result: the known keys, even stale; the last error when none.
func (f fetchedJWKS) result() (fetchedJWKS, error) {
	if f.set == nil {
		return f, f.err
	}
	return f, nil
}

func (k *clientKeys) download(ctx context.Context, uri string) (*jose.JSONWebKeySet, error) {
	if u, err := url.Parse(uri); err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("jwks_uri %q: https only", uri)
	}
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks_uri: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	if len(body) > jwksMaxBytes {
		return nil, errors.New("jwks_uri: the document is larger than 64 KiB")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwks_uri: not a JWK set: %w", err)
	}
	return &set, nil
}

// pickKey: the key the assertion names in its "kid", or the only key when it
// names none. Only an RSA public key for signatures will do (RS256, the one
// algorithm the library checks client assertions with).
func pickKey(set *jose.JSONWebKeySet, kid string) (*jose.JSONWebKey, error) {
	candidates := set.Keys
	if kid != "" {
		candidates = set.Key(kid)
	}
	var usable []jose.JSONWebKey
	for _, k := range candidates {
		pub, ok := k.Key.(*rsa.PublicKey)
		if ok && pub.N.BitLen() >= minClientRSABits && (k.Use == "" || k.Use == "sig") {
			usable = append(usable, k)
		}
	}
	if len(usable) != 1 {
		return nil, fmt.Errorf("no single RSA signing key of the client matches kid %q", kid)
	}
	return &usable[0], nil
}

// newKeysHTTPClient fetches jwks_uri. A realm administrator sets that URL:
// it must not let them reach the IdP's private network. The address is
// checked when dialled (a DNS answer cannot point elsewhere afterwards), no
// proxy, no redirect.
func newKeysHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: jwksFetchTimeout, Control: publicAddressOnly}
	return &http.Client{
		Timeout: jwksFetchTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   jwksFetchTimeout,
			ResponseHeaderTimeout: jwksFetchTimeout,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// notPublic: ranges IsPrivate does not cover. 100.64.0.0/10 (RFC 6598) is
// shared address space; the IPv6 ones carry an IPv4 address that a gateway
// would reach, and no key server needs them: refused whatever the IPv4 inside.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("64:ff9b:1::/48"), // local NAT64 (RFC 8215)
	netip.MustParsePrefix("2002::/16"),      // 6to4 (RFC 3056)
	netip.MustParsePrefix("::/96"),          // IPv4-compatible (deprecated)
}

// nat64: the well-known NAT64 prefix (RFC 6052). Behind DNS64, an IPv4-only
// host resolves to it: such an address is checked as the IPv4 it carries
// (64:ff9b::a00:1 is 10.0.0.1).
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func publicAddressOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
	checked := ip
	if nat64.Contains(ip) {
		b := ip.As16()
		checked = netip.AddrFrom4([4]byte(b[12:]))
	}
	if !checked.IsGlobalUnicast() || checked.IsPrivate() ||
		slices.ContainsFunc(notPublic, func(p netip.Prefix) bool { return p.Contains(checked) }) {
		return fmt.Errorf("jwks_uri: %s is not a public address", ip)
	}
	return nil
}
