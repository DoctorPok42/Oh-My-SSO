package pwnedpasswords_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // the Pwned Passwords range API is keyed by SHA-1
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/pwnedpasswords"
)

func TestClient(t *testing.T) {
	const leaked, padded = "a leaked passphrase", "a padded passphrase"
	var paths, padding []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		padding = append(padding, r.Header.Get("Add-Padding"))
		for _, line := range []struct {
			pw    string
			count int
		}{{leaked, 42}, {padded, 0}} {
			sum := fmt.Sprintf("%X", sha1.Sum([]byte(line.pw)))
			fmt.Fprintf(w, "%s:%d\r\n", sum[5:], line.count)
		}
	}))
	defer srv.Close()
	c := pwnedpasswords.New()
	c.URL = srv.URL + "/range/"
	ctx := context.Background()

	pwned, err := c.Pwned(ctx, leaked)
	require.NoError(t, err)
	require.True(t, pwned)
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(leaked)))
	require.Equal(t, "/range/"+sum[:5], paths[0], "only the 5 first hex digits are sent")

	pwned, err = c.Pwned(ctx, padded)
	require.NoError(t, err)
	require.False(t, pwned, "a padding line (count 0) is not a breach")

	pwned, err = c.Pwned(ctx, "never seen anywhere")
	require.NoError(t, err)
	require.False(t, pwned)
	require.Equal(t, []string{"true", "true", "true"}, padding)
}

func TestClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := pwnedpasswords.New()
	c.URL = srv.URL + "/range/"
	_, err := c.Pwned(context.Background(), "whatever")
	require.Error(t, err)
}
