package httpserver_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent"
	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	"sso.internal/sso/internal/adminapi"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 14, end to end: `idp-admin bootstrap`, the first admin activates the
// account and signs in to the admin console (OIDC on the master realm, TOTP
// enrollment forced), then drives the Admin API with the access token:
// create a realm, a group and an OIDC client in it. And the guardrails:
// step-up, self-lockout, last admin, system objects, revoked session.

const (
	adminConsoleURL = "https://admin.example.test"
	adminPassword   = "admin-console-password-42"
)

type recordingNotifier struct {
	mu     sync.Mutex
	events []domain.NotificationEvent
}

func (n *recordingNotifier) Notify(_ context.Context, e domain.NotificationEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, e)
}

func (n *recordingNotifier) kinds(k domain.NotificationKind) []domain.NotificationEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []domain.NotificationEvent
	for _, e := range n.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

type adminTestEnv struct {
	idp      *httptest.Server
	api      *httptest.Server
	admin    *service.AdminService
	sessions *service.SessionService
	audit    repository.AuditLogRepository
	users    repository.UserRepository
	clock    *fakeClock
	notifier *recordingNotifier
	oidc     *oidcTestEnv // reuses its browser helpers and TOTP clock
}

func setupAdminTestEnv(t *testing.T) *adminTestEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", startTestPostgres(t, ctx))
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Schema.Create(ctx))
	valkeyClient, err := valkeycache.New(startTestValkey(t, ctx))
	require.NoError(t, err)
	t.Cleanup(valkeyClient.Close)

	clock := &fakeClock{}
	notifier := &recordingNotifier{}
	km := localdev.New("test")
	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	clients := entstore.NewClientRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	attempts := entstore.NewLoginAttemptRepository(client)
	audit := entstore.NewAuditLogRepository(client)
	tokens := entstore.NewTokenRepository(client)
	signingKeys := entstore.NewSigningKeyRepository(client)
	access := entstore.NewAccessRepository(client)
	roles := entstore.NewRoleRepository(client)
	groups := entstore.NewGroupRepository(client)
	scopes := entstore.NewClientScopeRepository(client)
	limiter := valkeycache.NewRateLimiter(valkeyClient)

	sessions := service.NewSessionService(entstore.NewSessionRepository(client), settings, tokens,
		valkeycache.NewSessionCache(valkeyClient), service.WithClock(clock.Now))
	policy := service.NewMFAPolicyService(service.MFAPolicyDeps{Settings: settings, Clients: clients, Roles: roles,
		Policies: entstore.NewMfaPolicyRepository(client), Access: access, Audit: audit, Now: clock.Now})
	mfa := service.NewMFAService(service.MFADeps{
		Users: users, Methods: entstore.NewMfaMethodRepository(client), BackupCodes: entstore.NewMfaBackupCodeRepository(client),
		Sessions: sessions, Policy: policy, Envelope: service.NewEnvelopeService(signingKeys, km, "local_dev"),
		Store: valkeycache.NewMFAStore(valkeyClient), Limiter: limiter, LoginAttempts: attempts, Audit: audit,
		Realms: realms, Clients: clients, Now: clock.Now, Notifier: notifier,
	})
	auth := service.NewAuthService(users, attempts)
	rbac := service.NewRBACService(access, audit)
	consent := service.NewConsentService(service.ConsentDeps{Consents: entstore.NewConsentRepository(client), Clients: clients,
		Sessions: sessions, Tokens: tokens, Audit: audit}, service.WithConsentClock(clock.Now))
	idp := service.NewIdentityCore(service.IdentityCoreDeps{Auth: auth, Sessions: sessions, RBAC: rbac, Users: users,
		Clients: clients, Realms: realms, Tokens: tokens, SigningKeys: signingKeys, KeyManager: km, MFA: mfa,
		Consent: consent, Audit: audit}, service.WithIdentityCoreClock(clock.Now))
	rotation := service.NewKeyRotationService(signingKeys, entstore.NewKeyRotationLogRepository(client), settings, km, "local_dev")
	reset := service.NewPasswordResetService(service.PasswordResetDeps{Users: users,
		Tokens: entstore.NewPasswordResetTokenRepository(client), Sessions: sessions, Settings: settings, Audit: audit, Now: clock.Now})

	var router http.Handler
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	adapter, err := oidcadapter.New(oidcadapter.Config{PublicURL: ts.URL, SessionCookieName: httpserver.SessionCookieName, Now: clock.Now},
		idp, valkeycache.NewOIDCStore(valkeyClient))
	require.NoError(t, err)
	router = httpserver.New(auth, sessions, rbac, realms, clients, limiter,
		httpserver.WithMFA(mfa), httpserver.WithJWKS(idp), httpserver.WithOIDC(adapter), httpserver.WithPasswordReset(reset)).Router()

	admin := service.NewAdminService(service.AdminDeps{
		Realms: realms, Users: users, Clients: clients, Scopes: scopes, Roles: roles, Groups: groups,
		Permissions: entstore.NewPermissionRepository(client), Settings: settings, Audit: audit, Access: access,
		MfaMethods: entstore.NewMfaMethodRepository(client), Admin: entstore.NewAdminRepository(client),
		Sessions: sessions, KeyRotation: rotation, MFA: mfa, MFAPolicy: policy, PasswordReset: reset,
		Lockout:     service.NewLockoutService(service.LockoutDeps{Users: users, Settings: settings}),
		OIDCClients: service.NewOIDCClientService(clients, scopes, roles, groups),
		SAMLClients: service.NewSAMLClientService(clients, scopes, roles, groups),
		Notifier:    notifier, PublicURL: ts.URL,
		// The in-memory KeyManager is shared by everything in this test
		// process, so realms may get their keys here (see ensureSigningKey).
		KMSBackend: "test", Now: clock.Now,
	})
	api := httptest.NewServer(adminapi.New(adminapi.Config{PublicURL: ts.URL, Now: clock.Now}, adminapi.Deps{
		Admin: admin, Realms: realms, Users: users, Clients: clients, Tokens: tokens, Sessions: sessions,
		RBAC: rbac, MFA: mfa, Keys: idp, KeyRotation: rotation,
	}).Router())
	t.Cleanup(api.Close)

	return &adminTestEnv{idp: ts, api: api, admin: admin, sessions: sessions, audit: audit, users: users,
		clock: clock, notifier: notifier, oidc: &oidcTestEnv{ts: ts, clock: clock, realmURL: ts.URL + "/r/master"}}
}

// call sends one Admin API request with the admin's access token.
func (e *adminTestEnv) call(t *testing.T, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.api.URL+path, r)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// signIn runs the admin console's login: OIDC code flow + PKCE on the
// master realm. firstTime: the account has no factor yet, the login page
// asks for a TOTP enrollment (MFA is required in master).
func (e *adminTestEnv) signIn(t *testing.T, cfg *oauth2.Config, username string, totpSecret *string, opts ...oauth2.AuthCodeOption) *oauth2.Token {
	t.Helper()
	b := e.oidc.newBrowser(t)
	verifier := oauth2.GenerateVerifier()
	resp := b.get(cfg.AuthCodeURL("st", append(opts, oauth2.S256ChallengeOption(verifier))...))
	loginURL := resp.Request.URL.String()
	require.Contains(t, loginURL, "/r/master/oidc/login?id=")

	status, body := b.postJSON(e.oidc.realmURL+"/auth/login", map[string]any{"identifier": username, "password": adminPassword, "client_id": "sso-admin"})
	require.Equal(t, http.StatusOK, status, "%v", body)
	if *totpSecret == "" {
		require.Equal(t, "mfa_enrollment_required", body["status"])
		status, out := b.postJSON(e.oidc.realmURL+"/account/mfa/totp", map[string]string{"name": "phone"})
		require.Equal(t, http.StatusCreated, status, "%v", out)
		*totpSecret = out["secret"].(string)
		status, out = b.postJSON(e.oidc.realmURL+"/account/mfa/totp/"+out["method_id"].(string)+"/confirm",
			map[string]string{"code": e.oidc.totpCode(t, *totpSecret)})
		require.Equal(t, http.StatusOK, status, "%v", out)
	} else {
		require.Equal(t, "mfa_required", body["status"])
		status, out := b.postJSON(e.oidc.realmURL+"/auth/mfa/verify", map[string]string{"method": "totp", "code": e.oidc.totpCode(t, *totpSecret)})
		require.Equal(t, http.StatusOK, status, "%v", out)
	}
	code := codeFromRedirect(t, b.get(loginURL), cfg.RedirectURL, "st")
	tok, err := cfg.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, e.idp.Client()), code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	return tok
}

// activate chooses the password with an activation link (the reset page's JSON call).
func (e *adminTestEnv) activate(t *testing.T, link string) {
	t.Helper()
	u, err := url.Parse(link)
	require.NoError(t, err)
	token := strings.TrimPrefix(u.Fragment, "token=")
	raw, _ := json.Marshal(map[string]string{"token": token, "password": adminPassword})
	resp, err := e.idp.Client().Post(e.idp.URL+u.Path, "application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAdmin_Integration_DefinitionOfDone(t *testing.T) {
	e := setupAdminTestEnv(t)
	ctx := context.Background()

	// --- 1. bootstrap ---
	res, err := e.admin.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "root@example.test",
		AdminConsoleURL: adminConsoleURL, Actor: "cli:test@host"})
	require.NoError(t, err)
	require.NotEmpty(t, res.ClientSecret)
	require.Contains(t, res.ActivationURL, "/r/master/auth/reset-password#token=")
	require.Empty(t, res.SigningKeyWarning)

	// Before activation, bootstrap may run again (unfinished setup): new link,
	// client unchanged (no new secret).
	again, err := e.admin.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "root@example.test",
		AdminConsoleURL: "https://evil.example.test", Actor: "cli:test@host"})
	require.NoError(t, err)
	require.Empty(t, again.ClientSecret, "an existing client is never changed")
	require.NotEqual(t, res.ActivationURL, again.ActivationURL)

	// The first link stopped working; the new one works.
	e.activate(t, again.ActivationURL)

	// Once an account chose its password: never again.
	_, err = e.admin.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "other@example.test",
		AdminConsoleURL: adminConsoleURL, Actor: "cli:test@host"})
	require.ErrorIs(t, err, service.ErrAlreadyBootstrapped)

	// --- 2. the admin signs in to the console ---
	console := &oauth2.Config{ClientID: "sso-admin", ClientSecret: res.ClientSecret,
		RedirectURL: adminConsoleURL + "/auth/callback", Scopes: []string{"openid", "profile", "email", "offline_access"},
		Endpoint: oauth2.Endpoint{AuthURL: e.idp.URL + "/r/master/oidc/authorize", TokenURL: e.idp.URL + "/r/master/oidc/token",
			AuthStyle: oauth2.AuthStyleInHeader}}
	var secret string
	tok := e.signIn(t, console, "root", &secret)
	at := tok.AccessToken

	status, me := e.call(t, at, http.MethodGet, "/api/v1/me", nil)
	require.Equal(t, http.StatusOK, status, "%v", me)
	require.Equal(t, "root", me["user"].(map[string]any)["username"])
	require.Contains(t, me["permissions"], "client:write")
	require.Contains(t, me["permissions"], "realm:write")
	require.NotNil(t, me["step_up_fresh_until"])

	// --- 3. a realm, a group, an OIDC client ---
	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms", map[string]any{"name": "demo", "display_name": "Demo Corp"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms", map[string]any{"name": "master"})
	require.Equal(t, http.StatusConflict, status, "%v", out)

	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/groups", map[string]any{"name": "employees"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	groupID := out["id"].(string)

	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/clients", map[string]any{
		"protocol": "oidc", "name": "Payroll", "redirect_uris": []string{"https://payroll.example.test/callback"},
		"standard_scopes": []string{"profile", "email"}, "allowed_group_ids": []string{groupID}, "require_consent": true,
	})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	require.NotEmpty(t, out["secret"], "the secret is shown once, at creation")
	created := out["client"].(map[string]any)
	clientRef := created["id"].(string)
	require.True(t, strings.HasPrefix(created["client_id"].(string), "payroll-"), created["client_id"])
	require.Equal(t, true, created["require_consent"])
	require.Len(t, created["allowed_groups"], 1)

	// The secret never comes back.
	status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/clients/"+clientRef, nil)
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, out, "secret")
	require.Equal(t, true, out["oidc"].(map[string]any)["has_secret"])

	// A rule of the protocol is checked here too: http is only for localhost.
	status, out = e.call(t, at, http.MethodPatch, "/api/v1/realms/demo/clients/"+clientRef,
		map[string]any{"redirect_uris": []string{"http://payroll.example.test/callback"}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)

	// The audit log of demo tells who did it: an admin of master.
	status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?action=admin.client.create", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, 1, out["total"])
	entry := out["items"].([]any)[0].(map[string]any)
	require.Equal(t, "root", entry["actor"].(map[string]any)["username"])
	require.Equal(t, true, entry["actor"].(map[string]any)["admin"])
	require.Equal(t, "master", entry["details"].(map[string]any)["admin_realm"])

	// --- 4. guardrails ---
	status, users := e.call(t, at, http.MethodGet, "/api/v1/realms/master/users?q=root", nil)
	require.Equal(t, http.StatusOK, status)
	rootID := users["items"].([]any)[0].(map[string]any)["id"].(string)

	status, out = e.call(t, at, http.MethodPatch, "/api/v1/realms/master/users/"+rootID, map[string]any{"status": "suspended"})
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "self_change", out["error"])
	status, out = e.call(t, at, http.MethodPatch, "/api/v1/realms/master", map[string]any{"status": "inactive"})
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "system_realm", out["error"])

	status, list := e.call(t, at, http.MethodGet, "/api/v1/realms/master/clients", nil)
	require.Equal(t, http.StatusOK, status)
	adminClient := list["items"].([]any)[0].(map[string]any)
	require.Equal(t, "config", adminClient["managed_by"])
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/master/clients/"+adminClient["id"].(string)+"/secret", nil)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "managed_by_config", out["error"])

	status, groupsOut := e.call(t, at, http.MethodGet, "/api/v1/realms/master/groups", nil)
	require.Equal(t, http.StatusOK, status)
	for _, g := range groupsOut["items"].([]any) {
		g := g.(map[string]any)
		status, out = e.call(t, at, http.MethodDelete, "/api/v1/realms/master/groups/"+g["id"].(string), nil)
		require.Equal(t, http.StatusConflict, status, "group %s is a system group", g["name"])
	}

	// A second admin, invited (no e-mail here: the link comes back once).
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/master/users", map[string]any{
		"email": "alice@example.test", "profile": map[string]any{"given_name": "Alice"}, "send_email": false,
	})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	require.Equal(t, false, out["user"].(map[string]any)["has_password"])
	require.Contains(t, out["activation_url"], "#token=")
	aliceID := out["user"].(map[string]any)["id"].(string)

	// root cannot leave "admins" (self), and alice is not active admin yet.
	var adminsID string
	for _, g := range groupsOut["items"].([]any) {
		if g.(map[string]any)["name"] == "admins" {
			adminsID = g.(map[string]any)["id"].(string)
		}
	}
	status, out = e.call(t, at, http.MethodPut, "/api/v1/realms/master/users/"+rootID+"/groups", map[string]any{"group_ids": []string{}})
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "self_change", out["error"])
	status, out = e.call(t, at, http.MethodPut, "/api/v1/realms/master/users/"+aliceID+"/groups", map[string]any{"group_ids": []string{adminsID}})
	require.Equal(t, http.StatusOK, status, "%v", out)

	// An activated account never gets an activation link from an admin.
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/master/users/"+rootID+"/activation-link", map[string]any{})
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "already_activated", out["error"])

	// --- 5. step-up: changes need a recent second factor ---
	status, out = e.call(t, at, http.MethodPatch, "/api/v1/realms/master/settings", map[string]any{"mfa_step_up_max_age_minutes": 1})
	require.Equal(t, http.StatusOK, status, "%v", out)
	e.clock.Advance(2 * time.Minute) // the second factor is too old now
	status, _ = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/groups", nil)
	require.Equal(t, http.StatusOK, status, "reading needs no step-up")
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/groups", map[string]any{"name": "contractors"})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "step_up_required", out["error"])

	// The console sends the admin through the login page again (prompt=login).
	e.clock.Advance(30 * time.Second) // next TOTP window
	tok = e.signIn(t, console, "root", &secret, oauth2.SetAuthURLParam("prompt", "login"))
	status, out = e.call(t, tok.AccessToken, http.MethodPost, "/api/v1/realms/demo/groups", map[string]any{"name": "contractors"})
	require.Equal(t, http.StatusCreated, status, "%v", out)

	// --- 6. tokens ---
	// A revoked session cuts the API at once (the JWT itself is still valid).
	claims := jwtClaims(t, tok.AccessToken)
	require.NoError(t, e.sessions.Revoke(ctx, claims["sid"].(string), domain.SessionRevokedAdminRevoked))
	status, out = e.call(t, tok.AccessToken, http.MethodGet, "/api/v1/me", nil)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_token", out["error"])
	// No token, garbage token.
	status, _ = e.call(t, "", http.MethodGet, "/api/v1/me", nil)
	require.Equal(t, http.StatusUnauthorized, status)
	status, _ = e.call(t, "eyJhbGciOiJub25lIn0.e30.", http.MethodGet, "/api/v1/me", nil)
	require.Equal(t, http.StatusUnauthorized, status)

	// --- 7. break-glass recovery ---
	rec, err := e.admin.RecoverAdmin(ctx, service.RecoverAdminInput{Email: "root@example.test", Actor: "cli:test@host"})
	require.Error(t, err, "recovery never touches an existing account")
	rec, err = e.admin.RecoverAdmin(ctx, service.RecoverAdminInput{Email: "breakglass@example.test", Actor: "cli:test@host"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(rec.Username, "recovery-"))
	alerts := e.notifier.kinds(domain.NotificationAdminRecovery)
	require.Len(t, alerts, 2, "root and alice (both in admins) are alerted")
	logs, err := e.audit.ListByRealm(ctx, claimsRealm(t, e, "master"))
	require.NoError(t, err)
	found := false
	for _, l := range logs {
		if l.Action == "admin.recovery_admin" {
			found = true
			require.Equal(t, domain.AuditLogCritical, l.Level)
			require.Equal(t, "cli:test@host", l.Details["triggered_by"])
		}
	}
	require.True(t, found)
}

func jwtClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	require.NoError(t, err)
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
	return claims
}

func claimsRealm(t *testing.T, e *adminTestEnv, name string) string {
	t.Helper()
	r, err := e.admin.RealmByName(context.Background(), name)
	require.NoError(t, err)
	return r.ID
}
