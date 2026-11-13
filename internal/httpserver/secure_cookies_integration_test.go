package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/httpserver"
)

// Audit B-18: over https, the security cookies are __Host-<name>-<realm>
// (Path=/, no Domain), so that a neighbouring subdomain cannot plant a
// session of its choice. The test server is plain http: only the names and
// attributes the server writes are checked here (browsers enforce __Host-).
func TestSecureCookies_Integration(t *testing.T) {
	env := setupTestEnv(t, httpserver.WithPublicURL("https://sso.example.test"))
	realm := env.createRealm(t, "cookie-realm")
	env.createUser(t, realm.ID, "gina", "gina-password-123", domain.UserActive)
	env.createUser(t, realm.ID, "mallory", "mallory-password-123", domain.UserActive)

	signIn := func(user, password string) (session, device *http.Cookie, all []*http.Cookie) {
		t.Helper()
		resp := env.doLogin(t, realm.Name, user, password)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		for _, c := range resp.Cookies() {
			switch c.Name {
			case "__Host-sso_session-cookie-realm":
				session = c
			case "__Host-sso_device-cookie-realm":
				device = c
			}
		}
		return session, device, resp.Cookies()
	}

	whoAmI := func(cookies ...*http.Cookie) (int, string, []*http.Cookie) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/r/"+realm.Name+"/auth/session", nil)
		require.NoError(t, err)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var body struct {
			UserID string `json:"user_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.UserID, resp.Cookies()
	}

	session, device, all := signIn("gina", "gina-password-123")
	require.NotNil(t, session, "the session cookie is a __Host- one")
	require.NotNil(t, device, "so is the device cookie")
	for _, c := range []*http.Cookie{session, device} {
		require.Equal(t, "/", c.Path, "__Host- requires Path=/")
		require.Empty(t, c.Domain, "__Host- forbids Domain")
		require.True(t, c.Secure)
		require.True(t, c.HttpOnly)
	}
	removed := map[string]bool{}
	for _, c := range all {
		if c.MaxAge < 0 {
			removed[c.Name+" "+c.Path] = true
		}
	}
	require.True(t, removed["sso_session /r/cookie-realm"], "the former session cookie is removed")
	require.True(t, removed["sso_device /r/cookie-realm"], "the former device cookie is removed")

	code, gina, _ := whoAmI(&http.Cookie{Name: session.Name, Value: session.Value})
	require.Equal(t, http.StatusOK, code)
	require.NotEmpty(t, gina)

	// A neighbouring subdomain plants mallory's session under the old name:
	// gina's __Host- cookie wins, the planted one is not read.
	mallorySession, _, _ := signIn("mallory", "mallory-password-123")
	code, who, _ := whoAmI(
		&http.Cookie{Name: "sso_session", Value: mallorySession.Value},
		&http.Cookie{Name: session.Name, Value: session.Value},
	)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, gina, who)

	// A browser from before the upgrade (former name only): still signed in,
	// and moved to the __Host- cookie on the way.
	code, who, set := whoAmI(&http.Cookie{Name: "sso_session", Value: session.Value})
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, gina, who)
	var moved, formerGone bool
	for _, c := range set {
		if c.Name == session.Name && c.Value == session.Value && c.Path == "/" {
			moved = true
		}
		if c.Name == "sso_session" && c.MaxAge < 0 {
			formerGone = true
		}
	}
	require.True(t, moved, "the session cookie is written under its __Host- name")
	require.True(t, formerGone, "and the former one removed")

	// Sign-out removes both names.
	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/r/"+realm.Name+"/auth/logout", bytes.NewReader(nil))
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	cleared := map[string]bool{}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	require.True(t, cleared[session.Name])
	require.True(t, cleared["sso_session"])
	code, _, _ = whoAmI(&http.Cookie{Name: session.Name, Value: session.Value})
	require.Equal(t, http.StatusUnauthorized, code)
}
