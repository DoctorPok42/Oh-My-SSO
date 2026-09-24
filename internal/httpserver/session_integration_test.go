package httpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/sessioncache"
)

const testPassword = "correct-horse-battery-staple"

func (e *testEnv) loginAndGetCookie(t *testing.T, realmName, username string) *http.Cookie {
	t.Helper()
	resp := e.doLogin(t, realmName, username, testPassword)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	c := findSessionCookie(resp)
	require.NotNil(t, c, "login must set the session cookie")
	return c
}

func findSessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "sso_session" {
			return c
		}
	}
	return nil
}

func (e *testEnv) getSession(t *testing.T, realmName string, c *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.ts.URL+"/r/"+realmName+"/auth/session", nil)
	require.NoError(t, err)
	if c != nil {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (e *testEnv) logout(t *testing.T, realmName string, c *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/r/"+realmName+"/auth/logout", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (e *testEnv) sessionIDFromCookie(t *testing.T, realmName string, c *http.Cookie) string {
	t.Helper()
	resp := e.getSession(t, realmName, c)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	id, _ := body["session_id"].(string)
	require.NotEmpty(t, id)
	return id
}

func (e *testEnv) cacheKeyExists(t *testing.T, c *http.Cookie) bool {
	t.Helper()
	key := "session:{" + service.HashSessionToken(c.Value) + "}"
	n, err := e.valkey.Do(context.Background(), e.valkey.B().Exists().Key(key).Build()).ToInt64()
	require.NoError(t, err)
	return n == 1
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	defer resp.Body.Close()
	require.Equal(t, want, resp.StatusCode)
}

func TestSessions_Integration(t *testing.T) {
	env := setupTestEnv(t)

	t.Run("login sets a hardened session cookie", func(t *testing.T) {
		realm := env.createRealm(t, "cookie-realm")
		env.createUser(t, realm.ID, "alice", testPassword, domain.UserActive)

		c := env.loginAndGetCookie(t, realm.Name, "alice")

		require.NotEmpty(t, c.Value)
		require.True(t, c.HttpOnly)
		require.True(t, c.Secure)
		require.Equal(t, http.SameSiteLaxMode, c.SameSite)
		require.Equal(t, "/r/"+realm.Name, c.Path)
		require.Greater(t, c.MaxAge, 0)
	})

	t.Run("valid cookie gives access and fills the cache", func(t *testing.T) {
		realm := env.createRealm(t, "access-realm")
		env.createUser(t, realm.ID, "bob", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "bob")

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)
		require.True(t, env.cacheKeyExists(t, c), "first validation must fill Valkey")
	})

	t.Run("no cookie or random cookie is rejected", func(t *testing.T) {
		realm := env.createRealm(t, "nocookie-realm")

		assertStatus(t, env.getSession(t, realm.Name, nil), http.StatusUnauthorized)
		assertStatus(t, env.getSession(t, realm.Name, &http.Cookie{Name: "sso_session", Value: "abc"}), http.StatusUnauthorized)
	})

	t.Run("revoked session is rejected immediately", func(t *testing.T) {
		realm := env.createRealm(t, "revoke-realm")
		env.createUser(t, realm.ID, "carol", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "carol")

		sessionID := env.sessionIDFromCookie(t, realm.Name, c)
		require.True(t, env.cacheKeyExists(t, c))

		require.NoError(t, env.sessions.Revoke(context.Background(), sessionID, domain.SessionRevokedAdminRevoked))

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusUnauthorized)
	})

	t.Run("tombstone wins over a stale cache entry (race protection)", func(t *testing.T) {
		realm := env.createRealm(t, "race-realm")
		env.createUser(t, realm.ID, "dave", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "dave")
		sessionID := env.sessionIDFromCookie(t, realm.Name, c)

		require.NoError(t, env.sessions.Revoke(context.Background(), sessionID, domain.SessionRevokedAdminRevoked))

		cache := valkeycache.NewSessionCache(env.valkey)
		tokenHash := service.HashSessionToken(c.Value)
		require.NoError(t, cache.Fill(context.Background(), tokenHash, sessioncache.Entry{
			SessionID:      sessionID,
			RealmID:        realm.ID,
			Status:         domain.SessionActive,
			ExpiresAt:      time.Now().Add(time.Hour),
			LastActivityAt: time.Now(),
		}, time.Hour))

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusUnauthorized)
	})

	t.Run("logout revokes the session and clears the cookie", func(t *testing.T) {
		realm := env.createRealm(t, "logout-realm")
		env.createUser(t, realm.ID, "erin", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "erin")
		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)

		resp := env.logout(t, realm.Name, c)
		cleared := findSessionCookie(resp)
		assertStatus(t, resp, http.StatusNoContent)
		require.NotNil(t, cleared)
		require.Less(t, cleared.MaxAge, 0)

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusUnauthorized)
		assertStatus(t, env.logout(t, realm.Name, c), http.StatusNoContent)
	})

	t.Run("cookie from another realm is rejected", func(t *testing.T) {
		realmA := env.createRealm(t, "realm-a")
		realmB := env.createRealm(t, "realm-b")
		env.createUser(t, realmA.ID, "frank", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realmA.Name, "frank")

		assertStatus(t, env.getSession(t, realmB.Name, c), http.StatusUnauthorized)
	})

	t.Run("session is rejected after its absolute lifetime", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "maxlife-realm")
		env.createUser(t, realm.ID, "grace", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "grace")
		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)

		for elapsed := time.Duration(0); elapsed < 7*time.Hour+55*time.Minute; elapsed += 5 * time.Minute {
			env.clock.Advance(5 * time.Minute)
			assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)
		}
		env.clock.Advance(6 * time.Minute)

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusUnauthorized)
	})

	t.Run("session is rejected after the idle timeout", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "idle-realm")
		env.createUser(t, realm.ID, "heidi", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "heidi")
		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)

		env.clock.Advance(11 * time.Minute)

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusUnauthorized)
	})

	t.Run("activity keeps the session alive", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "keepalive-realm")
		env.createUser(t, realm.ID, "ivan", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "ivan")

		for i := 0; i < 3; i++ {
			env.clock.Advance(8 * time.Minute)
			assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)
		}
	})

	t.Run("app limits longer than the realm are rejected", func(t *testing.T) {
		realm := env.createRealm(t, "app-check-realm")
		ctx := context.Background()

		idle, maxMinutes := 10, 8*60
		require.NoError(t, env.sessions.CheckClientSessionLimits(ctx, realm.ID,
			service.ClientSessionLimitsFromMinutes(&idle, &maxMinutes)))

		tooIdle := 11
		require.ErrorIs(t, env.sessions.CheckClientSessionLimits(ctx, realm.ID,
			service.ClientSessionLimitsFromMinutes(&tooIdle, nil)), service.ErrClientSessionLimitTooLong)

		tooLong := 8*60 + 1
		require.ErrorIs(t, env.sessions.CheckClientSessionLimits(ctx, realm.ID,
			service.ClientSessionLimitsFromMinutes(nil, &tooLong)), service.ErrClientSessionLimitTooLong)
	})

	t.Run("app idle limit is stricter but does not kill the SSO session", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "app-idle-realm")
		env.createUser(t, realm.ID, "kate", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "kate")
		ctx := context.Background()

		idle := 5
		strict := service.ClientSessionLimitsFromMinutes(&idle, nil)

		_, err := env.sessions.ValidateForClient(ctx, realm.ID, c.Value, strict)
		require.NoError(t, err)

		env.clock.Advance(6 * time.Minute)
		_, err = env.sessions.ValidateForClient(ctx, realm.ID, c.Value, strict)
		require.ErrorIs(t, err, service.ErrReauthRequired)

		_, err = env.sessions.Validate(ctx, realm.ID, c.Value)
		require.NoError(t, err)
	})

	t.Run("app max lifetime forces reauthentication", func(t *testing.T) {
		t.Cleanup(env.clock.Reset)
		realm := env.createRealm(t, "app-maxlife-realm")
		env.createUser(t, realm.ID, "leo", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "leo")
		ctx := context.Background()

		maxMinutes := 30
		strict := service.ClientSessionLimitsFromMinutes(nil, &maxMinutes)

		for i := 0; i < 6; i++ {
			env.clock.Advance(5 * time.Minute)
			_, err := env.sessions.Validate(ctx, realm.ID, c.Value)
			require.NoError(t, err)
		}
		env.clock.Advance(time.Minute)

		_, err := env.sessions.ValidateForClient(ctx, realm.ID, c.Value, strict)
		require.ErrorIs(t, err, service.ErrReauthRequired)
	})

	t.Run("postgres stays the source of truth when valkey is empty", func(t *testing.T) {
		realm := env.createRealm(t, "flush-realm")
		env.createUser(t, realm.ID, "judy", testPassword, domain.UserActive)
		c := env.loginAndGetCookie(t, realm.Name, "judy")
		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)

		require.NoError(t, env.valkey.Do(context.Background(), env.valkey.B().Flushall().Build()).Error())

		assertStatus(t, env.getSession(t, realm.Name, c), http.StatusOK)
		require.True(t, env.cacheKeyExists(t, c), "cache must be re-filled after a miss")
	})
}
