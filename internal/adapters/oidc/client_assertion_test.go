package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
)

func testRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return k
}

func TestPickKey(t *testing.T) {
	a, b := testRSA(t, 2048), testRSA(t, 2048)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &a.PublicKey, KeyID: "a", Use: "sig"},
		{Key: &b.PublicKey, KeyID: "b"},
		{Key: &ec.PublicKey, KeyID: "ec"},
		{Key: &testRSA(t, 1024).PublicKey, KeyID: "short"},
		{Key: &a.PublicKey, KeyID: "enc", Use: "enc"},
	}}

	k, err := pickKey(set, "b")
	require.NoError(t, err)
	require.Equal(t, "b", k.KeyID)
	for _, kid := range []string{"ec", "short", "enc", "missing"} {
		_, err := pickKey(set, kid)
		require.Error(t, err, kid)
	}
	_, err = pickKey(set, "")
	require.Error(t, err, "no kid and several keys: ambiguous")

	one := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &a.PublicKey}}}
	k, err = pickKey(one, "")
	require.NoError(t, err, "no kid, one key: that one")
	require.Equal(t, &a.PublicKey, k.Key)
}

func TestPublicAddressOnly(t *testing.T) {
	// The last one: a public IPv4-only host behind DNS64 (93.184.215.14).
	for _, addr := range []string{"93.184.215.14:443", "[2606:4700::6810:84e5]:443", "[64:ff9b::5db8:d70e]:443"} {
		require.NoError(t, publicAddressOnly("tcp", addr, nil), addr)
	}
	for _, addr := range []string{
		"127.0.0.1:443", "10.1.2.3:443", "172.16.0.1:443", "192.168.1.1:443", "169.254.169.254:80",
		"100.64.0.1:443", "0.0.0.0:443", "[::1]:443", "[fd00::1]:443", "[fe80::1]:443", "[::ffff:10.0.0.1]:443",
		// IPv4 inside IPv6: NAT64 to 10.0.0.1 and to 100.64.0.1, local NAT64,
		// 6to4, IPv4-compatible.
		"[64:ff9b::a00:1]:443", "[64:ff9b::6440:1]:443", "[64:ff9b:1::a00:1]:443", "[2002:a00:1::1]:443", "[::a00:1]:443",
	} {
		require.Error(t, publicAddressOnly("tcp", addr, nil), addr)
	}
}

func TestClientKeys_JWKSURI(t *testing.T) {
	a, b := testRSA(t, 2048), testRSA(t, 2048)
	var served atomic.Value
	served.Store(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &a.PublicKey, KeyID: "a"}}})
	var hits atomic.Int32
	var down atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/jwks":
			_ = json.NewEncoder(w).Encode(served.Load())
		case "/big":
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("x", jwksMaxBytes) + `"}`))
		case "/moved":
			http.Redirect(w, r, "/jwks", http.StatusFound)
		}
	}))
	defer srv.Close()

	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	k := newClientKeys(func() time.Time { return now }, slog.Default())
	k.http = srv.Client() // the test server is on the loopback: no address check here
	k.http.CheckRedirect = newKeysHTTPClient().CheckRedirect
	app := &domain.ClientApp{ClientID: "batch", JWKSURI: srv.URL + "/jwks"}
	ctx := context.Background()

	key, err := k.key(ctx, app, "a")
	require.NoError(t, err)
	require.Equal(t, &a.PublicKey, key.Key)
	_, err = k.key(ctx, app, "a")
	require.NoError(t, err)
	require.EqualValues(t, 1, hits.Load(), "cached")

	// The client rotates to key b: an unknown kid fetches again, at most
	// once a minute.
	served.Store(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &b.PublicKey, KeyID: "b"}}})
	_, err = k.key(ctx, app, "b")
	require.Error(t, err, "fetched less than a minute ago")
	require.EqualValues(t, 1, hits.Load())
	now = now.Add(jwksRefetchAfter)
	key, err = k.key(ctx, app, "b")
	require.NoError(t, err)
	require.Equal(t, &b.PublicKey, key.Key)
	require.EqualValues(t, 2, hits.Load())

	// The key server goes down: the known keys stay usable past the cache
	// time, and it is not asked again more than once a minute.
	down.Store(true)
	now = now.Add(jwksCacheTTL)
	for range 3 {
		key, err = k.key(ctx, app, "b")
		require.NoError(t, err, "stale keys are kept")
		require.Equal(t, &b.PublicKey, key.Key)
	}
	_, err = k.key(ctx, app, "unknown")
	require.Error(t, err)
	require.EqualValues(t, 3, hits.Load(), "one failed read, then none for a minute (an unknown kid included)")
	now = now.Add(jwksRefetchAfter)
	_, err = k.key(ctx, app, "b")
	require.NoError(t, err)
	require.EqualValues(t, 4, hits.Load(), "tried again after a minute")
	down.Store(false)

	// A key server that never answered: the error, and no new read for a minute.
	gone := &domain.ClientApp{JWKSURI: srv.URL + "/jwks?gone"}
	down.Store(true)
	for range 2 {
		_, err = k.key(ctx, gone, "a")
		require.ErrorContains(t, err, "status 503")
	}
	require.EqualValues(t, 5, hits.Load())
	down.Store(false)

	for _, path := range []string{"/big", "/moved"} {
		_, err := k.key(ctx, &domain.ClientApp{JWKSURI: srv.URL + path}, "a")
		require.Error(t, err, path)
	}
	_, err = k.key(ctx, &domain.ClientApp{JWKSURI: "http://example.com/jwks"}, "a")
	require.ErrorContains(t, err, "https only")
}

// Two reads of one jwks_uri at once: the one that fails, ending last, must
// not bring back the keys the other one replaced.
func TestClientKeys_ConcurrentReads(t *testing.T) {
	old, rotated := testRSA(t, 2048), testRSA(t, 2048)
	var n atomic.Int32
	arrived, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &old.PublicKey, KeyID: "old"}}})
		case 2: // the slow read, which fails
			close(arrived)
			<-release
			http.Error(w, "down", http.StatusServiceUnavailable)
		default:
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rotated.PublicKey, KeyID: "new"}}})
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	k := newClientKeys(func() time.Time { return now }, slog.Default())
	k.http = srv.Client()
	app := &domain.ClientApp{JWKSURI: srv.URL}
	ctx := context.Background()
	_, err := k.key(ctx, app, "old")
	require.NoError(t, err)
	now = now.Add(jwksCacheTTL) // both reads below go to the server

	slow := make(chan error)
	go func() {
		_, err := k.fetch(ctx, app.JWKSURI, false)
		slow <- err
	}()
	<-arrived
	_, err = k.fetch(ctx, app.JWKSURI, false) // the fast read: the rotated key
	require.NoError(t, err)
	close(release)
	require.NoError(t, <-slow, "the slow read gives the keys known now")

	key, err := k.key(ctx, app, "new")
	require.NoError(t, err, "the rotated key stays")
	require.Equal(t, &rotated.PublicKey, key.Key)
}

func TestClientKeys_Inline(t *testing.T) {
	a := testRSA(t, 2048)
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &a.PublicKey, KeyID: "a"}}})
	require.NoError(t, err)
	k := newClientKeys(time.Now, slog.Default())
	key, err := k.key(context.Background(), &domain.ClientApp{JWKS: string(raw)}, "a")
	require.NoError(t, err)
	require.Equal(t, &a.PublicKey, key.Key)
}

// The library builds the access token, then the ID token, from one request:
// only the first gets the API resource as audience.
func TestIssuedAccessAudience(t *testing.T) {
	ar := &authRequest{ClientID: "app"}
	require.Equal(t, []string{"app"}, ar.GetAudience())
	ar.issued.token = &domain.Token{Audience: []string{"https://api.example.com"}}
	require.Equal(t, []string{"https://api.example.com"}, ar.GetAudience(), "access token JWT")
	ar.issued.built = true
	require.Equal(t, []string{"app"}, ar.GetAudience(), "ID token")

	sa := &serviceAccountRequest{token: &domain.Token{Subject: "batch"}}
	require.Equal(t, []string{"batch"}, sa.GetAudience())
	sa.token.Audience = []string{"https://api.example.com"}
	require.Equal(t, []string{"https://api.example.com"}, sa.GetAudience())
}
