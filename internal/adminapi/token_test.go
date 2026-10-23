package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
)

const (
	testIssuer = "https://sso.example.test/r/master"
	testKid    = "kid-1"
)

type staticKeys struct{ keys []*domain.SigningKey }

func (s staticKeys) PublicKeys(context.Context, string, domain.SigningKeyPurpose) ([]*domain.SigningKey, error) {
	return s.keys, nil
}

func pemPublic(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sign(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid))
	require.NoError(t, err)
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	out, err := obj.CompactSerialize()
	require.NoError(t, err)
	return out
}

func TestTokenVerifier(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	v := &tokenVerifier{
		keys: staticKeys{keys: []*domain.SigningKey{
			{Kid: testKid, KeyType: domain.SigningKeyRSA, PublicKey: pemPublic(t, &rsaKey.PublicKey)},
			{Kid: "kid-ec", KeyType: domain.SigningKeyEC, PublicKey: pemPublic(t, &ecKey.PublicKey)},
		}},
		issuer: testIssuer, audience: "sso-admin", now: func() time.Time { return now },
	}
	good := func() map[string]any {
		return map[string]any{
			"iss": testIssuer, "sub": "user-1", "aud": []string{"sso-admin"}, "client_id": "sso-admin",
			"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "jti": "jti-1", "sid": "session-1",
		}
	}
	with := func(k string, val any) map[string]any {
		c := good()
		if val == nil {
			delete(c, k)
		} else {
			c[k] = val
		}
		return c
	}
	ctx := context.Background()

	c, err := v.verify(ctx, "master-id", sign(t, rsaKey, jose.RS256, testKid, good()))
	require.NoError(t, err)
	require.Equal(t, "session-1", c.SessionID)
	require.Equal(t, "jti-1", c.JTI)

	// "aud" as a single string is fine too (RFC 7519).
	_, err = v.verify(ctx, "master-id", sign(t, rsaKey, jose.RS256, testKid, with("aud", "sso-admin")))
	require.NoError(t, err)

	// An EC key signs ES256.
	_, err = v.verify(ctx, "master-id", sign(t, ecKey, jose.ES256, "kid-ec", good()))
	require.NoError(t, err)

	refused := map[string]string{
		"signed by another key":          sign(t, otherKey, jose.RS256, testKid, good()),
		"unknown kid":                    sign(t, rsaKey, jose.RS256, "kid-unknown", good()),
		"wrong issuer (other realm)":     sign(t, rsaKey, jose.RS256, testKid, with("iss", "https://sso.example.test/r/demo")),
		"wrong audience":                 sign(t, rsaKey, jose.RS256, testKid, with("aud", []string{"payroll"})),
		"token of another client":        sign(t, rsaKey, jose.RS256, testKid, with("client_id", "payroll")),
		"expired":                        sign(t, rsaKey, jose.RS256, testKid, with("exp", now.Add(-time.Minute).Unix())),
		"no exp":                         sign(t, rsaKey, jose.RS256, testKid, with("exp", nil)),
		"not yet valid":                  sign(t, rsaKey, jose.RS256, testKid, with("nbf", now.Add(10*time.Minute).Unix())),
		"no sid":                         sign(t, rsaKey, jose.RS256, testKid, with("sid", nil)),
		"no jti":                         sign(t, rsaKey, jose.RS256, testKid, with("jti", nil)),
		"RS384 not accepted":             sign(t, rsaKey, jose.RS384, testKid, good()),
		"EC key, RSA header (confusion)": sign(t, rsaKey, jose.RS256, "kid-ec", good()),
		"garbage":                        "not.a.jwt",
	}
	// alg "none": header and payload, empty signature.
	b64 := func(v any) string { raw, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(raw) }
	refused["alg none"] = b64(map[string]string{"alg": "none", "kid": testKid}) + "." + b64(good()) + "."
	// HS256 with the public key as the HMAC secret (classic confusion attack).
	hmacSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(pemPublic(t, &rsaKey.PublicKey))},
		(&jose.SignerOptions{}).WithHeader("kid", testKid))
	require.NoError(t, err)
	payload, _ := json.Marshal(good())
	obj, err := hmacSigner.Sign(payload)
	require.NoError(t, err)
	refused["HS256 with the public key"], _ = obj.CompactSerialize()

	for name, tok := range refused {
		_, err := v.verify(ctx, "master-id", tok)
		require.ErrorIs(t, err, errInvalidToken, name)
	}
}

func TestAllowlist(t *testing.T) {
	_, n1, _ := net.ParseCIDR("10.0.0.0/24")
	s := &Server{cfg: Config{AllowedNets: []*net.IPNet{n1}}}
	ok := s.allowlist(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for addr, want := range map[string]int{
		"10.0.0.7:5000":  http.StatusNoContent,
		"10.0.1.7:5000":  http.StatusForbidden,
		"127.0.0.1:5000": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		req.RemoteAddr = addr
		req.Header.Set("X-Forwarded-For", "10.0.0.7") // never trusted
		rec := httptest.NewRecorder()
		ok.ServeHTTP(rec, req)
		require.Equal(t, want, rec.Code, addr)
	}
}

func TestRequireJSON(t *testing.T) {
	h := requireJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, c := range []struct {
		method, ct, body string
		want             int
	}{
		{http.MethodGet, "", "", http.StatusNoContent},
		{http.MethodPost, "application/json", "{}", http.StatusNoContent},
		{http.MethodPost, "", "", http.StatusNoContent}, // no body: nothing to parse
		{http.MethodPost, "text/plain", "{}", http.StatusUnsupportedMediaType},
		{http.MethodPatch, "application/x-www-form-urlencoded", "a=b", http.StatusUnsupportedMediaType},
	} {
		req := httptest.NewRequest(c.method, "/api/v1/realms", strings.NewReader(c.body))
		if c.ct != "" {
			req.Header.Set("Content-Type", c.ct)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, c.want, rec.Code, "%s %s", c.method, c.ct)
	}
}

func TestUnauthenticatedRequests(t *testing.T) {
	s := New(Config{PublicURL: "https://sso.example.test"}, Deps{})
	for _, h := range []string{"", "Basic abc", "Bearer "} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code, h)
		require.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
	}
	// The liveness probe needs nothing.
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}
