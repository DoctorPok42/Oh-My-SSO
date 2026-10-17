package httpserver_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"sso.internal/sso/ent"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/passkey"
	"sso.internal/sso/internal/passkey/passkeytest"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 9a Definition of Done, through HTTP, with a real Postgres and a real
// Valkey (testcontainers, Docker required):
// TOTP enrollment -> login with a TOTP -> login with a backup code ->
// login with an expired / invalid TOTP rejected. Plus step-up and a client
// policy.

type mfaTestEnv struct {
	ts      *httptest.Server
	realms  repository.RealmRepository
	users   repository.UserRepository
	clients repository.ClientRepository
	mfaPol  *service.MFAPolicyService
	clock   *fakeClock
}

func setupMFATestEnv(t *testing.T) *mfaTestEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	ctx := context.Background()

	dsn := startTestPostgres(t, ctx)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Schema.Create(ctx))

	valkeyClient, err := valkeycache.New(startTestValkey(t, ctx))
	require.NoError(t, err)
	t.Cleanup(valkeyClient.Close)

	clock := &fakeClock{}
	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	clients := entstore.NewClientRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	attempts := entstore.NewLoginAttemptRepository(client)
	audit := entstore.NewAuditLogRepository(client)
	limiter := valkeycache.NewRateLimiter(valkeyClient)

	sessions := service.NewSessionService(
		entstore.NewSessionRepository(client), settings, entstore.NewTokenRepository(client),
		valkeycache.NewSessionCache(valkeyClient), service.WithClock(clock.Now),
	)
	policy := service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: settings,
		Clients:  clients,
		Roles:    entstore.NewRoleRepository(client),
		Policies: entstore.NewMfaPolicyRepository(client),
		Access:   entstore.NewAccessRepository(client),
		Audit:    audit,
		Now:      clock.Now,
	})
	// Passkeys: the software authenticator answers from this origin.
	passkeys, err := passkey.New(passkey.Config{RPID: "sso.test", RPOrigins: []string{passkeyTestOrigin}})
	require.NoError(t, err)

	mfa := service.NewMFAService(service.MFADeps{
		Users:         users,
		Methods:       entstore.NewMfaMethodRepository(client),
		BackupCodes:   entstore.NewMfaBackupCodeRepository(client),
		Sessions:      sessions,
		Policy:        policy,
		Envelope:      service.NewEnvelopeService(entstore.NewSigningKeyRepository(client), localdev.New("test"), "local_dev"),
		Store:         valkeycache.NewMFAStore(valkeyClient),
		Limiter:       limiter,
		LoginAttempts: attempts,
		Audit:         audit,
		Realms:        realms,
		Clients:       clients,
		Passkeys:      passkeys,
		Now:           clock.Now,
	})
	rbac := service.NewRBACService(entstore.NewAccessRepository(client), audit)

	srv := httpserver.New(service.NewAuthService(users, attempts), sessions, rbac, realms, clients, limiter,
		httpserver.WithMFA(mfa))
	// TLS: the cookies are Secure, and a cookie jar only sends them over https.
	ts := httptest.NewTLSServer(srv.Router())
	t.Cleanup(ts.Close)

	return &mfaTestEnv{ts: ts, realms: realms, users: users, clients: clients, mfaPol: policy, clock: clock}
}

func startTestPostgres(t *testing.T, ctx context.Context) string {
	t.Helper()
	c, err := postgres.Run(ctx, "postgres:16",
		postgres.WithDatabase("sso_test"), postgres.WithUsername("sso"), postgres.WithPassword("sso"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn
}

func startTestValkey(t *testing.T, ctx context.Context) string {
	t.Helper()
	c, err := testcontainers.Run(ctx, "valkey/valkey:latest",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp")),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	return host + ":" + port.Port()
}

const passkeyTestOrigin = "https://sso.test"

// browser is an HTTP client with its own cookie jar, like a browser tab.
type browser struct {
	t     *testing.T
	c     *http.Client
	base  string
	realm string
}

func (e *mfaTestEnv) newBrowser(t *testing.T, realm string) *browser {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := e.ts.Client()
	c.Jar = jar
	return &browser{t: t, c: c, base: e.ts.URL + "/r/" + realm, realm: realm}
}

func (b *browser) do(method, path string, body any) (int, map[string]any) {
	b.t.Helper()
	status, raw := b.doRaw(method, path, body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return status, out
}

// doRaw sends body (a value to encode, or json.RawMessage as is) and
// returns the raw response body.
func (b *browser) doRaw(method, path string, body any) (int, []byte) {
	b.t.Helper()
	var rd io.Reader
	if raw, ok := body.(json.RawMessage); ok {
		rd = bytes.NewReader(raw)
	} else if body != nil {
		data, err := json.Marshal(body)
		require.NoError(b.t, err)
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, b.base+path, rd)
	require.NoError(b.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.c.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(b.t, err)
	return resp.StatusCode, raw
}

func (b *browser) hasCookie(name string) bool {
	for _, c := range b.c.Jar.Cookies(mustURL(b.t, b.base+"/auth/mfa/verify")) {
		if c.Name == name {
			return true
		}
	}
	return false
}

func (e *mfaTestEnv) code(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, e.clock.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	return c
}

func TestMFA_HTTP_DefinitionOfDone_Integration(t *testing.T) {
	env := setupMFATestEnv(t)
	ctx := context.Background()

	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "mfa-realm"})
	require.NoError(t, err)
	hash, err := service.HashPassword("correct-horse-battery-staple")
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "alice", Email: "alice@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "bob", Email: "bob@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	login := map[string]string{"identifier": "alice", "password": "correct-horse-battery-staple"}

	b := env.newBrowser(t, realm.Name)

	// --- 1. Plain login, then TOTP enrollment ------------------------------
	status, body := b.do(http.MethodPost, "/auth/login", login)
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "authenticated", body["status"])

	status, body = b.do(http.MethodPost, "/account/mfa/totp", map[string]string{"name": "Pixel"})
	require.Equal(t, http.StatusCreated, status, body)
	secret := body["secret"].(string)
	methodID := body["method_id"].(string)
	require.Contains(t, body["qr_code_png"], "data:image/png;base64,")

	status, body = b.do(http.MethodPost, "/account/mfa/totp/"+methodID+"/confirm", map[string]string{"code": "000000"})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_mfa_code", body["error"])

	status, body = b.do(http.MethodPost, "/account/mfa/totp/"+methodID+"/confirm", map[string]string{"code": env.code(t, secret)})
	require.Equal(t, http.StatusOK, status, body)
	codes := body["backup_codes"].([]any)
	require.Len(t, codes, 10)

	status, body = b.do(http.MethodGet, "/account/mfa", nil)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, body["methods"], 1)

	_, _ = b.do(http.MethodPost, "/auth/logout", nil)
	env.clock.Advance(30 * time.Second) // next TOTP window

	// --- 2. Login with a correct TOTP ---------------------------------------
	status, body = b.do(http.MethodPost, "/auth/login", login)
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "mfa_required", body["status"])
	require.Equal(t, []any{"totp", "backup_codes"}, body["methods"])
	require.Nil(t, body["user_id"], "nothing about the account before the second factor")
	require.True(t, b.hasCookie("sso_mfa"))
	status, _ = b.do(http.MethodGet, "/auth/session", nil)
	require.Equal(t, http.StatusUnauthorized, status, "no session yet")

	status, body = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "totp", "code": "111111"})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_mfa_code", body["error"])
	require.EqualValues(t, 4, body["attempts_remaining"])

	good := env.code(t, secret)
	status, body = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "totp", "code": good})
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "authenticated", body["status"])
	require.False(t, b.hasCookie("sso_mfa"), "challenge cookie removed")

	status, body = b.do(http.MethodGet, "/auth/session", nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, body["mfa_verified"])
	require.Equal(t, "totp", body["mfa_method"])

	// The same code on a new login: replay refused.
	_, _ = b.do(http.MethodPost, "/auth/logout", nil)
	_, body = b.do(http.MethodPost, "/auth/login", login)
	require.Equal(t, "mfa_required", body["status"])
	status, body = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "totp", "code": good})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_mfa_code", body["error"])

	// --- 3. Login with a backup code ----------------------------------------
	status, body = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "backup_code", "code": codes[0].(string)})
	require.Equal(t, http.StatusOK, status, body)
	require.EqualValues(t, 9, body["backup_codes_remaining"])

	_, _ = b.do(http.MethodPost, "/auth/logout", nil)
	_, _ = b.do(http.MethodPost, "/auth/login", login)
	status, _ = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "backup_code", "code": codes[0].(string)})
	require.Equal(t, http.StatusUnauthorized, status, "a backup code works once")

	// --- 4. Expired TOTP ----------------------------------------------------
	expired, err := totp.GenerateCodeCustom(secret, env.clock.Now().Add(-90*time.Second), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	status, body = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "totp", "code": expired})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_mfa_code", body["error"])

	// --- 5. Step-up before removing a factor -------------------------------
	env.clock.Advance(30 * time.Second)
	status, _ = b.do(http.MethodPost, "/auth/mfa/verify", map[string]string{"method": "totp", "code": env.code(t, secret)})
	require.Equal(t, http.StatusOK, status)

	// 11 minutes later (with activity in between, so the session is alive),
	// the MFA verification is too old for a sensitive action.
	env.clock.Advance(5 * time.Minute)
	status, _ = b.do(http.MethodGet, "/auth/session", nil)
	require.Equal(t, http.StatusOK, status)
	env.clock.Advance(6 * time.Minute)

	status, body = b.do(http.MethodDelete, "/account/mfa/"+methodID, nil)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "step_up_required", body["error"])
	require.EqualValues(t, 600, body["max_age_seconds"])

	status, body = b.do(http.MethodPost, "/auth/step-up", map[string]string{"method": "totp", "code": env.code(t, secret)})
	require.Equal(t, http.StatusOK, status, body)

	status, _ = b.do(http.MethodDelete, "/account/mfa/"+methodID, nil)
	require.Equal(t, http.StatusNoContent, status)

	_, body = b.do(http.MethodGet, "/account/mfa", nil)
	require.Empty(t, body["methods"])
	require.EqualValues(t, 0, body["backup_codes"].(map[string]any)["total"], "codes go with the last factor")

	// --- 6. A client that requires MFA -------------------------------------
	app, err := env.clients.Create(ctx, repository.CreateClientAppParams{RealmID: realm.ID, Name: "Payroll", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)
	clientID := "payroll"
	_, err = env.clients.Update(ctx, app.ID, repository.UpdateClientAppParams{ClientID: &clientID})
	require.NoError(t, err)
	_, err = env.mfaPol.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: realm.ID, ClientRef: app.ID, Policy: domain.ClientAppMFARequired})
	require.NoError(t, err)

	// Back to the real time: the database stamps a new session's
	// last_activity_at with the real clock.
	env.clock.Reset()
	bob := env.newBrowser(t, realm.Name)
	status, body = bob.do(http.MethodPost, "/auth/login", map[string]string{"identifier": "bob", "password": "correct-horse-battery-staple", "client_id": "payroll"})
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "mfa_enrollment_required", body["status"])

	status, body = bob.do(http.MethodGet, "/auth/mfa/status?client_id=payroll", nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, body["required"])
	require.Equal(t, false, body["satisfied"])
	require.Equal(t, true, body["enrollment_required"])
	require.Equal(t, []any{"client:payroll"}, body["sources"])

	status, body = bob.do(http.MethodPost, "/auth/login", map[string]string{"identifier": "bob", "password": "correct-horse-battery-staple", "client_id": "nope"})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "unknown_client", body["error"])
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

// Step 9b Definition of Done, over HTTP: passkey enrollment -> login with
// the passkey as second factor (software authenticator, real signatures).
func TestMFA_HTTP_Passkey_Integration(t *testing.T) {
	env := setupMFATestEnv(t)
	ctx := context.Background()

	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "passkey-realm"})
	require.NoError(t, err)
	hash, err := service.HashPassword("correct-horse-battery-staple")
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "alice", Email: "alice@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	login := map[string]string{"identifier": "alice", "password": "correct-horse-battery-staple"}
	phone := passkeytest.New(passkeyTestOrigin)
	b := env.newBrowser(t, realm.Name)

	// --- enrollment ------------------------------------------------------------
	status, body := b.do(http.MethodPost, "/auth/login", login)
	require.Equal(t, http.StatusOK, status, body)

	status, options := b.doRaw(http.MethodPost, "/account/mfa/webauthn/register/options", map[string]string{"kind": "passkey", "name": "iPhone"})
	require.Equal(t, http.StatusOK, status, string(options))
	require.Contains(t, string(options), `"residentKey":"required"`)
	credential, err := phone.Create(options)
	require.NoError(t, err)

	status, body = b.do(http.MethodPost, "/account/mfa/webauthn/register/verify", json.RawMessage(credential))
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "passkey", body["method"].(map[string]any)["type"])
	require.Equal(t, "iPhone", body["method"].(map[string]any)["name"])
	require.Len(t, body["backup_codes"], 10)

	status, body = b.do(http.MethodPost, "/account/mfa/webauthn/register/verify", json.RawMessage(credential))
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "webauthn_ceremony_expired", body["error"], "a ceremony is answered once")

	// --- login with the passkey -----------------------------------------------
	_, _ = b.do(http.MethodPost, "/auth/logout", nil)
	status, body = b.do(http.MethodPost, "/auth/login", login)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "mfa_required", body["status"])
	require.Equal(t, []any{"passkey", "backup_codes"}, body["methods"])

	status, options = b.doRaw(http.MethodPost, "/auth/mfa/webauthn/options", map[string]string{})
	require.Equal(t, http.StatusOK, status, string(options))
	assertion, err := phone.Get(options)
	require.NoError(t, err)
	status, body = b.do(http.MethodPost, "/auth/mfa/webauthn/verify", json.RawMessage(assertion))
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "authenticated", body["status"])
	require.Equal(t, "passkey", body["mfa_method"])
	require.False(t, b.hasCookie("sso_mfa"))

	status, body = b.do(http.MethodGet, "/auth/session", nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "passkey", body["mfa_method"])

	// --- step-up with the passkey ---------------------------------------------
	status, options = b.doRaw(http.MethodPost, "/auth/step-up/webauthn/options", map[string]string{})
	require.Equal(t, http.StatusOK, status, string(options))
	assertion, err = phone.Get(options)
	require.NoError(t, err)
	status, body = b.do(http.MethodPost, "/auth/step-up/webauthn/verify", json.RawMessage(assertion))
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "passkey", body["mfa_method"])

	// --- a replayed assertion is refused ---------------------------------------
	_, _ = b.do(http.MethodPost, "/auth/logout", nil)
	_, _ = b.do(http.MethodPost, "/auth/login", login)
	status, _ = b.doRaw(http.MethodPost, "/auth/mfa/webauthn/options", map[string]string{})
	require.Equal(t, http.StatusOK, status)
	status, body = b.do(http.MethodPost, "/auth/mfa/webauthn/verify", json.RawMessage(assertion))
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_mfa_code", body["error"])

	// --- no challenge cookie, no options ---------------------------------------
	stranger := env.newBrowser(t, realm.Name)
	status, body = stranger.do(http.MethodPost, "/auth/mfa/webauthn/options", map[string]string{})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "mfa_challenge_expired", body["error"])
}
