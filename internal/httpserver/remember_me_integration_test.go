package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// "Keep me signed in": the cookie, the session durations, the sign-in page
// and the second factor, end to end.

const rememberedLifetime = 30 * 24 * time.Hour

func (e *testEnv) doLoginRemember(t *testing.T, realmName, identifier string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{"identifier": identifier, "password": testPassword, "remember_me": true})
	require.NoError(t, err)
	resp, err := http.Post(e.ts.URL+"/r/"+realmName+"/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	return resp
}

// requirePersistent: the cookie survives a browser restart and expires
// with the remembered session.
func requirePersistent(t *testing.T, c *http.Cookie) {
	t.Helper()
	require.NotNil(t, c)
	require.InDelta(t, rememberedLifetime.Seconds(), float64(c.MaxAge), 120)
	require.WithinDuration(t, time.Now().Add(rememberedLifetime), c.Expires, 2*time.Minute)
}

// requireBrowserSession: no Max-Age, no Expires, the browser drops the
// cookie when it closes.
func requireBrowserSession(t *testing.T, c *http.Cookie) {
	t.Helper()
	require.NotNil(t, c)
	require.Zero(t, c.MaxAge)
	require.True(t, c.Expires.IsZero(), "no Expires attribute, got %s", c.RawExpires)
}

func TestRememberMe_Integration(t *testing.T) {
	env := setupTestEnv(t)

	t.Run("ticked: persistent cookie, the session survives days without use", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "remember-realm")
		env.createUser(t, realm.ID, "alice", testPassword, domain.UserActive)

		resp := env.doLoginRemember(t, realm.Name, "alice")
		c := findSessionCookie(resp)
		var login map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&login))
		assertStatus(t, resp, http.StatusOK)
		requirePersistent(t, c)
		require.Equal(t, true, login["remember_me"])

		env.clock.Advance(2 * 24 * time.Hour)
		resp = env.getSession(t, realm.Name, c)
		var sess map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&sess))
		assertStatus(t, resp, http.StatusOK)
		require.Equal(t, true, sess["remember_me"])
	})

	t.Run("not ticked: browser-session cookie, gone after 10 minutes idle", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "no-remember-realm")
		env.createUser(t, realm.ID, "bob", testPassword, domain.UserActive)

		c := env.loginAndGetCookie(t, realm.Name, "bob")
		requireBrowserSession(t, c)

		env.clock.Advance(11 * time.Minute)
		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusUnauthorized)
	})
}

// --- through the OIDC sign-in page ---------------------------------------------

// postJSONCookies is postJSON, plus the cookies the response sets.
func (b *oidcBrowser) postJSONCookies(u string, body any) (int, map[string]any, []*http.Cookie) {
	b.t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := b.c.Post(u, "application/json", bytes.NewReader(raw))
	require.NoError(b.t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Cookies()
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// restart simulates closing and reopening the browser: a new browser that
// only has the persistent cookies among those given.
func (e *oidcTestEnv) restart(t *testing.T, cookies []*http.Cookie) *oidcBrowser {
	t.Helper()
	b := e.newBrowser(t)
	jar, ok := b.c.Jar.(*cookiejar.Jar)
	require.True(t, ok)
	u, err := url.Parse(e.realmURL)
	require.NoError(t, err)
	var kept []*http.Cookie
	for _, c := range cookies {
		if c.MaxAge > 0 || !c.Expires.IsZero() {
			kept = append(kept, c)
		}
	}
	jar.SetCookies(u, kept)
	return b
}

func TestOIDC_Integration_RememberMe(t *testing.T) {
	e := setupOIDCTestEnv(t)
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)
	pkce := func() oauth2.AuthCodeOption { return oauth2.S256ChallengeOption(oauth2.GenerateVerifier()) }
	credentials := func(remember bool) map[string]any {
		return map[string]any{"identifier": "alice", "password": oidcPassword, "client_id": webClientID, "remember_me": remember}
	}

	t.Run("the sign-in page offers it", func(t *testing.T) {
		resp, body := e.newBrowser(t).page(web.AuthCodeURL("s", pkce()))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, body, `id="remember-me"`)
		require.Contains(t, body, "up to 30 days")
	})

	t.Run("kept signed in: hours later, a restarted browser gets in without a password", func(t *testing.T) {
		t.Cleanup(e.clock.Reset)
		b := e.newBrowser(t)
		resp := b.get(web.AuthCodeURL("s1", pkce()))
		loginURL := resp.Request.URL.String()
		status, body, cookies := b.postJSONCookies(e.realmURL+"/auth/login", credentials(true))
		require.Equal(t, http.StatusOK, status, "%v", body)
		requirePersistent(t, cookieNamed(cookies, "sso_session"))
		codeFromRedirect(t, b.get(loginURL), webRedirectURI, "s1")

		e.clock.Advance(3 * time.Hour)
		again := e.restart(t, cookies)
		codeFromRedirect(t, again.get(web.AuthCodeURL("s2", pkce())), webRedirectURI, "s2")
	})

	t.Run("not kept: the cookie dies with the browser, and the session after 10 minutes idle", func(t *testing.T) {
		t.Cleanup(e.clock.Reset)
		b := e.newBrowser(t)
		b.get(web.AuthCodeURL("s3", pkce()))
		status, body, cookies := b.postJSONCookies(e.realmURL+"/auth/login", credentials(false))
		require.Equal(t, http.StatusOK, status, "%v", body)
		requireBrowserSession(t, cookieNamed(cookies, "sso_session"))

		resp, page := e.restart(t, cookies).page(web.AuthCodeURL("s4", pkce()))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, page, `data-mode="login"`, "restarted browser: sign in again")

		e.clock.Advance(11 * time.Minute)
		resp, page = b.page(web.AuthCodeURL("s5", pkce()))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, page, `data-mode="login"`, "same browser, 11 minutes idle: sign in again")
	})

	t.Run("prompt=login still asks for the password", func(t *testing.T) {
		b := e.newBrowser(t)
		b.get(web.AuthCodeURL("s6", pkce()))
		status, _, _ := b.postJSONCookies(e.realmURL+"/auth/login", credentials(true))
		require.Equal(t, http.StatusOK, status)

		resp, page := b.page(web.AuthCodeURL("s7", pkce(), oauth2.SetAuthURLParam("prompt", "login")))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, page, `data-mode="login"`)
	})

	t.Run("the choice survives the second factor", func(t *testing.T) {
		t.Cleanup(e.clock.Reset)
		// alice adds an authenticator app (from a session of her own).
		setup := e.newBrowser(t)
		e.loginAndGetCode(t, setup, web, "alice", pkce())
		status, out := setup.postJSON(e.realmURL+"/account/mfa/totp", map[string]string{"name": "phone"})
		require.Equal(t, http.StatusCreated, status, "%v", out)
		secret, methodID := out["secret"].(string), out["method_id"].(string)
		status, out = setup.postJSON(e.realmURL+"/account/mfa/totp/"+methodID+"/confirm", map[string]string{"code": e.totpCode(t, secret)})
		require.Equal(t, http.StatusOK, status, "%v", out)
		e.clock.Advance(30 * time.Second) // next TOTP code

		b := e.newBrowser(t)
		resp := b.get(web.AuthCodeURL("s8", pkce()))
		loginURL := resp.Request.URL.String()
		status, body, cookies := b.postJSONCookies(e.realmURL+"/auth/login", credentials(true))
		require.Equal(t, http.StatusOK, status, "%v", body)
		require.Equal(t, "mfa_required", body["status"])
		require.Nil(t, cookieNamed(cookies, "sso_session"), "no session before the second factor")

		status, body, cookies = b.postJSONCookies(e.realmURL+"/auth/mfa/verify", map[string]string{"method": "totp", "code": e.totpCode(t, secret)})
		require.Equal(t, http.StatusOK, status, "%v", body)
		requirePersistent(t, cookieNamed(cookies, "sso_session"))
		codeFromRedirect(t, b.get(loginURL), webRedirectURI, "s8")
	})
}

func TestOIDC_Integration_RememberMeTurnedOff(t *testing.T) {
	e := setupOIDCTestEnv(t)
	ctx := context.Background()
	settings := entstore.NewInstanceSettingsRepository(e.ent)
	st, err := settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: e.realm.ID})
	require.NoError(t, err)
	off := false
	_, err = settings.Update(ctx, st.ID, repository.UpdateInstanceSettingsParams{RememberMeEnabled: &off})
	require.NoError(t, err)

	web := e.oauth(webClientID, e.webSecret, webRedirectURI)
	b := e.newBrowser(t)
	resp, page := b.page(web.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `data-mode="login"`)
	require.NotContains(t, page, `id="remember-me"`, "not offered")

	// Asking anyway (an old page, a crafted request) gives a normal session.
	status, body, cookies := b.postJSONCookies(e.realmURL+"/auth/login",
		map[string]any{"identifier": "alice", "password": oidcPassword, "client_id": webClientID, "remember_me": true})
	require.Equal(t, http.StatusOK, status, "%v", body)
	require.Nil(t, body["remember_me"])
	requireBrowserSession(t, cookieNamed(cookies, "sso_session"))
}
