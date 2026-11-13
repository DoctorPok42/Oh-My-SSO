package httpserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
)

// listNetworks applies one list to every realm, as the service does.
type listNetworks struct {
	allow []string
	err   error
	calls int
}

func (n *listNetworks) Allows(_ context.Context, _ string, ip string) (bool, error) {
	n.calls++
	if n.err != nil {
		return false, n.err
	}
	return service.IPAllowed(n.allow, ip), nil
}

// A sign-in from outside the realm's IP allowlist is refused before the
// handler runs: no password check, no rate limit, no lockout (B-14). The
// server below has no auth service at all: reaching the handler with a
// valid body would panic, an empty body answers 400 before using it.
func TestSignInNetwork_Login(t *testing.T) {
	realms := &jwksRealms{byName: map[string]*domain.Realm{
		"acme": {ID: "realm-acme", Name: "acme", Status: domain.RealmActive},
	}}
	nets := &listNetworks{allow: []string{"10.0.0.0/8"}}
	srv := httpserver.New(nil, nil, nil, realms, nil, nil, httpserver.WithSignInNetworks(nets))

	login := func(from, body string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/r/acme/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = from + ":4242"
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)
		var out struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&out)
		return rec.Code, out.Error
	}

	code, msg := login("203.0.113.9", `{"identifier":"admin","password":"guess"}`)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, "network_not_allowed", msg)

	code, msg = login("10.1.2.3", `{}`)
	require.Equal(t, http.StatusBadRequest, code, "an allowed address reaches the handler")
	require.Equal(t, "invalid_request", msg)

	// The list cannot be read: refused, never let through.
	nets.err = errors.New("database down")
	code, msg = login("10.1.2.3", `{"identifier":"admin","password":"guess"}`)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Equal(t, "internal_error", msg)
	require.Equal(t, 3, nets.calls)
}
