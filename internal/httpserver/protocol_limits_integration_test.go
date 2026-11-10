package httpserver_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/httpserver"
)

// clientPost: a request to an OAuth endpoint with HTTP Basic client
// authentication. refresh_token: the library checks the secret before the
// token.
func clientPost(t *testing.T, e *oidcTestEnv, endpoint, clientID, secret string) *http.Response {
	t.Helper()
	resp, err := e.ts.Client().Do(clientRequest(endpoint, clientID, secret))
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func clientRequest(endpoint, clientID, secret string) *http.Request {
	form := url.Values{"token": {"not-a-token"}, "grant_type": {"refresh_token"}, "refresh_token": {"not-a-token"}}
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://spa.example.com")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	return req
}

func requireTooManyResp(t *testing.T, resp *http.Response, maxWait time.Duration) {
	t.Helper()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	secs, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	require.NoError(t, err)
	require.True(t, secs >= 1 && secs <= int(maxWait.Seconds()), "Retry-After = %d", secs)
	require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "rate_limited", body["error"])
}

// The whole chain with the default limits: the OIDC library calls our
// storage; Valkey counts every request that sends a secret before it runs
// and forgets those whose client proved its secret; the 11th attempt of a
// client_id from one address is refused (429) before the library, even
// with the right secret.
func TestOIDC_Integration_ClientAuthRateLimit(t *testing.T) {
	e := setupOIDCTestEnv(t)
	window := httpserver.DefaultProtocolLimits.ClientFailuresPerIP.Window

	t.Run("wrong secrets", func(t *testing.T) {
		endpoints := []string{e.disc.TokenEndpoint, e.disc.IntrospectionEndpoint, e.disc.RevocationEndpoint}
		for i := 0; i < 10; i++ {
			resp := clientPost(t, e, endpoints[i%3], webClientID, "wrong-"+strconv.Itoa(i))
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "attempt %d", i+1)
		}
		requireTooManyResp(t, clientPost(t, e, e.disc.IntrospectionEndpoint, webClientID, e.webSecret), window)
		requireTooManyResp(t, clientPost(t, e, e.disc.TokenEndpoint, webClientID, e.webSecret), window)
	})

	t.Run("unknown client_id", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			require.Equal(t, http.StatusUnauthorized, clientPost(t, e, e.disc.IntrospectionEndpoint, "ghost", "x").StatusCode)
		}
		requireTooManyResp(t, clientPost(t, e, e.disc.IntrospectionEndpoint, "ghost", "x"), window)
	})

	t.Run("another client is not affected", func(t *testing.T) {
		resp := clientPost(t, e, e.disc.IntrospectionEndpoint, partnerClientID, e.partnerSecret)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// A client that proves its secret gives its hit back: far more
// introspections than the per-address limit, all answered.
func TestOIDC_Integration_AuthenticatedClientsAreNotLimitedPerAddress(t *testing.T) {
	limits := httpserver.DefaultProtocolLimits
	limits.OIDCPerIP = httpserver.RateRule{Max: 3, Window: time.Minute}
	e := setupOIDCTestEnv(t, httpserver.WithProtocolLimits(limits))

	for i := 0; i < 15; i++ {
		resp := clientPost(t, e, e.disc.IntrospectionEndpoint, partnerClientID, e.partnerSecret)
		require.Equal(t, http.StatusOK, resp.StatusCode, "introspection %d", i+1)
	}
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusUnauthorized, clientPost(t, e, e.disc.IntrospectionEndpoint, "ghost", "x").StatusCode)
	}
	requireTooManyResp(t, clientPost(t, e, e.disc.IntrospectionEndpoint, partnerClientID, e.partnerSecret), time.Minute)
}

// Valkey's check-and-count is atomic: of a burst of parallel guesses, no
// more than the limit reach the library.
func TestOIDC_Integration_ParallelGuessesAreCounted(t *testing.T) {
	limits := httpserver.DefaultProtocolLimits
	limits.ClientFailuresPerIP = httpserver.RateRule{Max: 5, Window: time.Minute}
	e := setupOIDCTestEnv(t, httpserver.WithProtocolLimits(limits))

	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := -1 // transport error
			if resp, err := e.ts.Client().Do(clientRequest(e.disc.TokenEndpoint, webClientID, "guess")); err == nil {
				code = resp.StatusCode
				resp.Body.Close()
			}
			mu.Lock()
			codes[code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Equal(t, map[int]int{http.StatusUnauthorized: 5, http.StatusTooManyRequests: 35}, codes)
}
