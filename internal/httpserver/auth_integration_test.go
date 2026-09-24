package httpserver_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/ent"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/storage/entstore"
)

type testEnv struct {
	ts       *httptest.Server
	realms   repository.RealmRepository
	users    repository.UserRepository
	sessions *service.SessionService
	valkey   valkey.Client
	clock    *fakeClock
}

type fakeClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

func (c *fakeClock) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = 0
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}

	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:16",
		postgres.WithDatabase("sso_test"),
		postgres.WithUsername("sso"),
		postgres.WithPassword("sso"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(context.Background()) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.Schema.Create(ctx))

	valkeyContainer, err := testcontainers.Run(ctx, "valkey/valkey:latest",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp")),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = valkeyContainer.Terminate(context.Background()) })

	valkeyHost, err := valkeyContainer.Host(ctx)
	require.NoError(t, err)
	valkeyPort, err := valkeyContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	valkeyClient, err := valkeycache.New(valkeyHost + ":" + valkeyPort.Port())
	require.NoError(t, err)
	t.Cleanup(valkeyClient.Close)

	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	authService := service.NewAuthService(users, entstore.NewLoginAttemptRepository(client))

	clock := &fakeClock{}
	sessionService := service.NewSessionService(
		entstore.NewSessionRepository(client),
		entstore.NewInstanceSettingsRepository(client),
		valkeycache.NewSessionCache(valkeyClient),
		service.WithClock(clock.Now),
	)

	srv := httpserver.New(authService, sessionService, realms, valkeycache.NewRateLimiter(valkeyClient))
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	return &testEnv{
		ts:       ts,
		realms:   realms,
		users:    users,
		sessions: sessionService,
		valkey:   valkeyClient,
		clock:    clock,
	}
}

func (e *testEnv) createRealm(t *testing.T, name string) *domain.Realm {
	t.Helper()
	r, err := e.realms.Create(context.Background(), repository.CreateRealmParams{Name: name})
	require.NoError(t, err)
	return r
}

func (e *testEnv) createUser(t *testing.T, realmID, username, password string, status domain.UserStatus) *domain.User {
	t.Helper()
	hash, err := service.HashPassword(password)
	require.NoError(t, err)

	u, err := e.users.Create(context.Background(), repository.CreateUserParams{
		RealmID:      realmID,
		Username:     username,
		Email:        username + "@example.test",
		PasswordHash: hash,
		Status:       status,
	})
	require.NoError(t, err)
	return u
}

func (e *testEnv) doLogin(t *testing.T, realmName, identifier, password string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"identifier": identifier,
		"password":   password,
	})
	require.NoError(t, err)

	resp, err := http.Post(e.ts.URL+"/r/"+realmName+"/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	return resp
}

func decodeError(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body["error"]
}

func TestAuthLogin_Integration(t *testing.T) {
	env := setupTestEnv(t)

	t.Run("login réussi", func(t *testing.T) {
		realm := env.createRealm(t, "success-realm")
		env.createUser(t, realm.ID, "alice", "correct-horse-battery-staple", domain.UserActive)

		resp := env.doLogin(t, realm.Name, "alice", "correct-horse-battery-staple")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		require.NotEmpty(t, body["user_id"])
	})

	t.Run("mot de passe invalide", func(t *testing.T) {
		realm := env.createRealm(t, "badpass-realm")
		env.createUser(t, realm.ID, "bob", "the-real-password", domain.UserActive)

		resp := env.doLogin(t, realm.Name, "bob", "wrong-password")
		defer resp.Body.Close()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Equal(t, "invalid_credentials", decodeError(t, resp))
	})

	t.Run("compte suspendu", func(t *testing.T) {
		realm := env.createRealm(t, "suspended-realm")
		env.createUser(t, realm.ID, "carol", "some-password", domain.UserSuspended)

		resp := env.doLogin(t, realm.Name, "carol", "some-password")
		defer resp.Body.Close()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		require.Equal(t, "invalid_credentials", decodeError(t, resp))
	})

	t.Run("rate limit déclenché après N tentatives", func(t *testing.T) {
		realm := env.createRealm(t, "ratelimit-realm")
		env.createUser(t, realm.ID, "dave", "the-real-password", domain.UserActive)

		for i := 0; i < 5; i++ {
			resp := env.doLogin(t, realm.Name, "dave", "wrong-password")
			resp.Body.Close()
		}

		resp := env.doLogin(t, realm.Name, "dave", "wrong-password")
		defer resp.Body.Close()

		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		require.Equal(t, "rate_limited", decodeError(t, resp))
	})
}
