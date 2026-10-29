package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// resolve runs Middleware on a request from peer (host:port) with headers,
// and returns what FromRequest reads behind it.
func resolve(t *testing.T, res Resolver, peer string, headers map[string][]string) string {
	t.Helper()
	var got string
	h := res.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = FromRequest(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = peer
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func mustParse(t *testing.T, proxies, header string) Resolver {
	t.Helper()
	res, err := Parse(proxies, header)
	require.NoError(t, err)
	return res
}

func TestNoTrustedProxyIgnoresHeaders(t *testing.T) {
	res := Resolver{} // the default: TRUSTED_PROXIES empty
	got := resolve(t, res, "203.0.113.9:4321", map[string][]string{
		"X-Forwarded-For": {"1.2.3.4"},
		"X-Real-Ip":       {"5.6.7.8"},
		"True-Client-Ip":  {"9.9.9.9"},
	})
	require.Equal(t, "203.0.113.9", got, "a client must not choose its own address")
}

func TestXFFFromTrustedProxy(t *testing.T) {
	res := mustParse(t, "10.0.0.2", "")

	got := resolve(t, res, "10.0.0.2:5555", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}})
	require.Equal(t, "198.51.100.7", got)

	// The client sent its own X-Forwarded-For, the proxy appended the real
	// address: the rightmost untrusted entry wins, not the forged one.
	got = resolve(t, res, "10.0.0.2:5555", map[string][]string{"X-Forwarded-For": {"6.6.6.6, 198.51.100.7"}})
	require.Equal(t, "198.51.100.7", got)
}

func TestXFFSkipsEveryTrustedHop(t *testing.T) {
	// Cloudflare -> nginx -> idp: both proxies are listed.
	res := mustParse(t, "10.0.0.2, 172.16.0.0/12", "")
	got := resolve(t, res, "10.0.0.2:5555", map[string][]string{"X-Forwarded-For": {"198.51.100.7, 172.20.1.1"}})
	require.Equal(t, "198.51.100.7", got)
}

func TestXFFFromUntrustedPeerIsIgnored(t *testing.T) {
	res := mustParse(t, "10.0.0.2", "")
	got := resolve(t, res, "203.0.113.9:4321", map[string][]string{"X-Forwarded-For": {"1.2.3.4"}})
	require.Equal(t, "203.0.113.9", got, "only the listed proxies may set the address")
}

func TestTrustedProxyWithoutUsableHeaderFallsBackToPeer(t *testing.T) {
	res := mustParse(t, "10.0.0.2", "")
	require.Equal(t, "10.0.0.2", resolve(t, res, "10.0.0.2:5555", nil))
	require.Equal(t, "10.0.0.2", resolve(t, res, "10.0.0.2:5555",
		map[string][]string{"X-Forwarded-For": {"not-an-ip"}}))
}

func TestSingleIPHeaderFromTrustedProxy(t *testing.T) {
	res := mustParse(t, "10.0.0.2", "cf-connecting-ip")

	got := resolve(t, res, "10.0.0.2:5555", map[string][]string{
		"Cf-Connecting-Ip": {"198.51.100.7"},
		"X-Forwarded-For":  {"6.6.6.6"}, // not the configured header: ignored
	})
	require.Equal(t, "198.51.100.7", got)

	got = resolve(t, res, "203.0.113.9:4321", map[string][]string{"Cf-Connecting-Ip": {"1.2.3.4"}})
	require.Equal(t, "203.0.113.9", got)
}

func TestIPv4MappedPeerMatchesIPv4Proxy(t *testing.T) {
	// A dual-stack listener shows IPv4 peers as ::ffff:a.b.c.d.
	res := mustParse(t, "10.0.0.2", "")
	got := resolve(t, res, "[::ffff:10.0.0.2]:5555", map[string][]string{"X-Forwarded-For": {"198.51.100.7"}})
	require.Equal(t, "198.51.100.7", got)
}

func TestIPv6(t *testing.T) {
	res := mustParse(t, "2001:db8::/32", "")
	got := resolve(t, res, "[2001:db8::1]:5555", map[string][]string{"X-Forwarded-For": {"2001:db9::42"}})
	require.Equal(t, "2001:db9::42", got)
}

func TestFromRequestWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:4321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	require.Equal(t, "203.0.113.9", FromRequest(req))

	req.RemoteAddr = "203.0.113.9" // no port
	require.Equal(t, "203.0.113.9", FromRequest(req))
}

func TestParse(t *testing.T) {
	res, err := Parse(" 10.0.0.7 , 172.16.0.0/12,,2001:db8::1 ", "")
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.7/32", "172.16.0.0/12", "2001:db8::1/128"}, res.prefixStrings())
	require.True(t, res.TrustsProxies())

	res, err = Parse("", "")
	require.NoError(t, err)
	require.False(t, res.TrustsProxies())

	// Host bits are dropped: 10.1.2.3/8 means 10.0.0.0/8.
	res, err = Parse("10.1.2.3/8", "")
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.0/8"}, res.prefixStrings())

	for _, bad := range []string{"10.0.0", "10.0.0.0/33", "localhost", "*"} {
		_, err := Parse(bad, "")
		require.Error(t, err, bad)
	}

	_, err = Parse("", "X-Real-IP")
	require.Error(t, err, "a header without trusted proxies would never be read")

	_, err = Parse("10.0.0.2", "x-forwarded-for")
	require.Error(t, err, "X-Forwarded-For is a list, not a single-IP header")
}
