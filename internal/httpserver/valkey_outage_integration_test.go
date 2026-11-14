package httpserver_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/cache/fallback"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/cache/valkey/valkeytest"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/health"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/storage/entstore"
)

// TestSignInDuringValkeyOutage_Integration (audit B-11): Valkey cut off for
// real (its connections closed, new ones refused). Signing in goes on in the
// degraded mode, with the wiring of app.BuildCore; the same server without
// it answers 500, as before.
func TestSignInDuringValkeyOutage_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	ctx := context.Background()

	db, err := sql.Open("pgx", startTestPostgres(t, ctx))
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Schema.Create(ctx))

	proxy := valkeytest.NewProxy(t, startTestValkey(t, ctx))
	raw, err := valkeycache.New(proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(raw.Close)
	vk, guard := valkeycache.Guarded(raw)

	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	sessionRepo := entstore.NewSessionRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	lockout := service.NewLockoutService(service.LockoutDeps{
		Users:    users,
		Unknown:  fallback.NewLockoutStore(valkeycache.NewLockoutStore(vk), nil),
		History:  sessionRepo,
		Settings: settings,
	})
	auth := service.NewAuthService(users, entstore.NewLoginAttemptRepository(client), service.WithLockout(lockout))
	sessions := service.NewSessionService(sessionRepo, settings, entstore.NewTokenRepository(client),
		valkeycache.NewSessionCache(vk))
	rbac := service.NewRBACService(entstore.NewAccessRepository(client), entstore.NewAuditLogRepository(client))
	clients := entstore.NewClientRepository(client)

	limits := httpserver.DefaultProtocolLimits
	limits.LoginFailuresPerIP = httpserver.RateRule{Max: 3, Window: 15 * time.Minute}
	srv := httpserver.New(auth, sessions, rbac, realms, clients,
		fallback.NewLimiter(valkeycache.NewRateLimiter(vk), nil),
		httpserver.WithProtocolLimits(limits),
		httpserver.WithReadiness(health.Check{Name: "Valkey", Degrades: true, Check: func(ctx context.Context) error {
			return vk.Do(ctx, vk.B().Ping().Build()).Error()
		}}),
	)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	env := &testEnv{ts: ts, realms: realms, users: users, sessions: sessions}

	// Before B-11: the same server with Valkey's rate limiter alone.
	bare := httptest.NewServer(httpserver.New(auth, sessions, rbac, realms, clients,
		valkeycache.NewRateLimiter(raw), httpserver.WithProtocolLimits(limits)).Router())
	t.Cleanup(bare.Close)
	bareEnv := &testEnv{ts: bare}

	realm := env.createRealm(t, "valkey-outage")
	env.createUser(t, realm.ID, "alice", "correct-horse-battery-staple", domain.UserActive)
	status := func(e *testEnv, user, password string) (int, string) {
		resp := e.doLogin(t, realm.Name, user, password)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			require.NotEmpty(t, resp.Cookies(), "a session cookie")
			return resp.StatusCode, ""
		}
		return resp.StatusCode, decodeError(t, resp)
	}

	code, _ := status(env, "alice", "correct-horse-battery-staple")
	require.Equal(t, http.StatusOK, code, "Valkey up")

	proxy.Down()
	code, _ = status(env, "alice", "correct-horse-battery-staple")
	require.Equal(t, http.StatusOK, code, "signing in goes on while Valkey is down")
	require.ErrorIs(t, guard.Err(), fallback.ErrUnavailable)

	code, _ = status(bareEnv, "alice", "correct-horse-battery-staple")
	require.Equal(t, http.StatusInternalServerError, code, "without the degraded mode: 500 (the bug)")

	// An unknown identifier answers as a known one: the lockout counters of
	// unknown identifiers are in memory too (no 500 that would tell them apart).
	code, reason := status(env, "nobody", "whatever")
	require.Equal(t, http.StatusUnauthorized, code)
	require.Equal(t, "invalid_credentials", reason)
	code, reason = status(env, "alice", "wrong")
	require.Equal(t, http.StatusUnauthorized, code)
	require.Equal(t, "invalid_credentials", reason)
	// The failures of an address are still limited (3 here), in memory.
	code, _ = status(env, "alice", "wrong")
	require.Equal(t, http.StatusUnauthorized, code)
	code, reason = status(env, "alice", "wrong")
	require.Equal(t, http.StatusTooManyRequests, code)
	require.Equal(t, "rate_limited", reason)

	resp, err := http.Get(ts.URL + "/readyz")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "kept by the orchestrator")
	require.JSONEq(t, `{"status":"degraded"}`, string(body))

	// Valkey is back: its counters are used again (this address has none
	// there), once the next probe (every 2 s) gets an answer.
	proxy.Up(t)
	require.Eventually(t, func() bool {
		code, _ := status(env, "alice", "correct-horse-battery-staple")
		return code == http.StatusOK
	}, 15*time.Second, 200*time.Millisecond)
	require.NoError(t, guard.Err())
}
