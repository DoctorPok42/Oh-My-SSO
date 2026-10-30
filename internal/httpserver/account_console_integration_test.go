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
	"regexp"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"

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

// The account console (Step 14c) on a real database: PostgreSQL + Valkey.

type accountTestEnv struct {
	mfaTestEnv
	consents repository.ConsentRepository
}

func setupAccountTestEnv(t *testing.T) *accountTestEnv {
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
	tokens := entstore.NewTokenRepository(client)
	consents := entstore.NewConsentRepository(client)
	limiter := valkeycache.NewRateLimiter(valkeyClient)

	trusted := service.NewTrustedDeviceService(service.TrustedDeviceDeps{
		Devices: entstore.NewTrustedDeviceRepository(client), Settings: settings, Audit: audit, Now: clock.Now,
	})
	sessions := service.NewSessionService(
		entstore.NewSessionRepository(client), settings, tokens,
		valkeycache.NewSessionCache(valkeyClient), service.WithClock(clock.Now),
		service.WithAuditLog(audit), service.WithRevocationObserver(trusted),
	)
	policy := service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: settings, Clients: clients, Roles: entstore.NewRoleRepository(client),
		Policies: entstore.NewMfaPolicyRepository(client), Access: entstore.NewAccessRepository(client),
		Audit: audit, Now: clock.Now,
	})
	passkeys, err := passkey.New(passkey.Config{RPID: "sso.test", RPOrigins: []string{passkeyTestOrigin}})
	require.NoError(t, err)
	mfa := service.NewMFAService(service.MFADeps{
		Users: users, Methods: entstore.NewMfaMethodRepository(client),
		BackupCodes: entstore.NewMfaBackupCodeRepository(client), Sessions: sessions, Policy: policy,
		Envelope: service.NewEnvelopeService(entstore.NewSigningKeyRepository(client), localdev.New("test"), "local_dev"),
		Store:    valkeycache.NewMFAStore(valkeyClient), Limiter: limiter, LoginAttempts: attempts, Audit: audit,
		Realms: realms, Clients: clients, Passkeys: passkeys, TrustedDevices: trusted, Now: clock.Now,
	})
	consent := service.NewConsentService(service.ConsentDeps{
		Consents: consents, Clients: clients, Sessions: sessions, Tokens: tokens, Audit: audit,
	})
	account := service.NewAccountService(service.AccountDeps{
		Users: users, Admin: entstore.NewAdminRepository(client), Settings: settings, Clients: clients,
		ClientScopes: entstore.NewClientScopeRepository(client), Tokens: tokens, LoginAttempts: attempts,
		Audit: audit, Sessions: sessions, Consents: consent, TrustedDevices: trusted,
		Policy: service.NewPasswordPolicyService(settings), Now: clock.Now,
	})
	rbac := service.NewRBACService(entstore.NewAccessRepository(client), audit)

	srv := httpserver.New(service.NewAuthService(users, attempts), sessions, rbac, realms, clients, limiter,
		httpserver.WithMFA(mfa), httpserver.WithAccountConsole(account))
	// TLS: the cookies are Secure, and a cookie jar only sends them over https.
	ts := httptest.NewTLSServer(srv.Router())
	t.Cleanup(ts.Close)

	return &accountTestEnv{
		mfaTestEnv: mfaTestEnv{ts: ts, realms: realms, users: users, clients: clients, mfaPol: policy, clock: clock},
		consents:   consents,
	}
}

// tab is one browser: its own cookie jar. It does not follow redirects, so
// that tests see the 303 of each form.
type tab struct {
	t    *testing.T
	c    *http.Client
	root string // https://127.0.0.1:port
	base string // root + /r/<realm>
}

func (e *accountTestEnv) newTab(t *testing.T, realm string) *tab {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{
		Transport: e.ts.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &tab{t: t, c: c, root: e.ts.URL, base: e.ts.URL + "/r/" + realm}
}

func (b *tab) send(req *http.Request) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.c.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(b.t, err)
	return resp, string(raw)
}

// get: path is relative to /r/<realm>, or absolute when it starts with /r/.
func (b *tab) get(path string) (*http.Response, string) {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.url(path), nil)
	require.NoError(b.t, err)
	return b.send(req)
}

func (b *tab) post(path string, form url.Values, header http.Header) (*http.Response, string) {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.url(path), strings.NewReader(form.Encode()))
	require.NoError(b.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	return b.send(req)
}

// api calls the JSON API of the sign-in pages.
func (b *tab) api(method, path string, body any) (int, []byte) {
	b.t.Helper()
	var rd io.Reader
	if raw, ok := body.(json.RawMessage); ok {
		rd = bytes.NewReader(raw)
	} else if body != nil {
		data, err := json.Marshal(body)
		require.NoError(b.t, err)
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, b.url(path), rd)
	require.NoError(b.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, raw := b.send(req)
	return resp.StatusCode, []byte(raw)
}

func (b *tab) url(path string) string {
	if strings.HasPrefix(path, "/r/") {
		return b.root + path
	}
	return b.base + path
}

func (b *tab) login(identifier, password string) {
	b.t.Helper()
	status, body := b.api(http.MethodPost, "/auth/login", map[string]string{"identifier": identifier, "password": password})
	require.Equal(b.t, http.StatusOK, status, string(body))
}

func (b *tab) sessionID() (int, string) {
	b.t.Helper()
	status, raw := b.api(http.MethodGet, "/auth/session", nil)
	var out struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(raw, &out)
	return status, out.SessionID
}

func (b *tab) cookie(path, name string) string {
	for _, c := range b.c.Jar.Cookies(mustURL(b.t, b.root+path)) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfOf(t *testing.T, html string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(html)
	require.NotNil(t, m, "no CSRF token in the page")
	return m[1]
}

var htmx = http.Header{"Hx-Request": {"true"}}

func TestAccountConsole_DefinitionOfDone_Integration(t *testing.T) {
	env := setupAccountTestEnv(t)
	ctx := context.Background()

	acme, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "acme", DisplayName: "Acme Corp"})
	require.NoError(t, err)
	beta, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "beta", DisplayName: "Beta Labs"})
	require.NoError(t, err)
	const pw = "correct-horse-battery-staple"
	hash, err := service.HashPassword(pw)
	require.NoError(t, err)
	alice, err := env.users.Create(ctx, repository.CreateUserParams{RealmID: acme.ID, Username: "alice", Email: "alice@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: acme.ID, Username: "bob", Email: "bob@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: beta.ID, Username: "carol", Email: "carol@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)

	laptop := env.newTab(t, "acme")

	// --- no session: the sign-in page, at the console's address --------------
	resp, page := laptop.get("/account")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "to manage your account")
	require.Contains(t, page, `id="password-form"`)
	require.NotContains(t, page, `id="main"`)

	resp, _ = laptop.post("/account/profile", url.Values{"given_name": {"X"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "a form without a session goes back to the console")

	laptop.login("alice", pw)
	require.Equal(t, "acme", laptop.cookie("/r/acme/account", "sso_realms"), "the organization menu remembers acme")

	// --- profile ---------------------------------------------------------------
	resp, page = laptop.get("/account")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "alice@example.test")
	require.Contains(t, page, "Acme Corp")
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	require.Contains(t, resp.Header.Get("Content-Security-Policy"), "script-src 'self'")
	csrf := csrfOf(t, page)

	// CSRF: no token, another site (Fetch Metadata), another Origin.
	resp, page = laptop.post("/account/profile", url.Values{"given_name": {"Mallory"}}, nil)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Contains(t, page, "Request refused")
	resp, _ = laptop.post("/account/profile", url.Values{"given_name": {"Mallory"}, "csrf": {csrf}},
		http.Header{"Sec-Fetch-Site": {"cross-site"}})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp, _ = laptop.post("/account/profile", url.Values{"given_name": {"Mallory"}, "csrf": {csrf}},
		http.Header{"Origin": {"https://evil.example"}})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	u, err := env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Nil(t, u.Profile["given_name"], "nothing changed")

	resp, _ = laptop.post("/account/profile", url.Values{"given_name": {" Alice "}, "family_name": {"Martin"}, "csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "/r/acme/account", resp.Header.Get("Location"))
	_, page = laptop.get("/account")
	require.Contains(t, page, "Your name was saved.")
	require.Contains(t, page, `value="Alice"`)
	_, page = laptop.get("/account")
	require.NotContains(t, page, "Your name was saved.", "a notice shows once")
	u, err = env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Equal(t, "Alice Martin", u.Profile["name"])

	resp, page = laptop.post("/account/profile", url.Values{"given_name": {strings.Repeat("a", 101)}, "csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, strings.HasPrefix(page, `<form id="profile-form"`), "htmx: only the form")
	require.Contains(t, page, "at most 100 characters")

	// --- sessions: sign out another device, never someone else's ---------------
	phone := env.newTab(t, "acme")
	phone.login("alice", pw)
	_, phoneSession := phone.sessionID()
	bobTab := env.newTab(t, "acme")
	bobTab.login("bob", pw)
	_, bobSession := bobTab.sessionID()

	_, page = laptop.get("/account/sessions")
	revokeRe := regexp.MustCompile(`/sessions/([0-9a-f-]{36})/revoke`)
	ids := map[string]bool{}
	for _, m := range revokeRe.FindAllStringSubmatch(page, -1) {
		ids[m[1]] = true
	}
	require.Equal(t, map[string]bool{phoneSession: true}, ids, "one other session, and not the current one")
	require.Contains(t, page, "This session")

	resp, page = laptop.post("/account/sessions/"+bobSession+"/revoke", url.Values{"csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "That item no longer exists.")
	status, _ := bobTab.sessionID()
	require.Equal(t, http.StatusOK, status, "bob is still signed in")

	resp, page = laptop.post("/account/sessions/"+phoneSession+"/revoke", url.Values{"csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, strings.HasPrefix(page, `<section class="card" id="sessions">`), page)
	require.Contains(t, page, `hx-swap-oob="true"`)
	require.Contains(t, page, "That session was signed out.")
	require.NotContains(t, page, phoneSession)
	status, _ = phone.sessionID()
	require.Equal(t, http.StatusUnauthorized, status, "the phone is signed out")

	// --- add a passkey (just signed in, no second step yet: no step-up) --------
	resp, page = laptop.get("/account/security/passkey")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `id="passkey-form"`)
	require.Contains(t, page, `data-api="/r/acme"`)
	key := passkeytest.New(passkeyTestOrigin)
	status, options := laptop.api(http.MethodPost, "/account/mfa/webauthn/register/options", map[string]string{"kind": "passkey", "name": "iPhone"})
	require.Equal(t, http.StatusOK, status, string(options))
	credential, err := key.Create(options)
	require.NoError(t, err)
	status, raw := laptop.api(http.MethodPost, "/account/mfa/webauthn/register/verify", json.RawMessage(credential))
	require.Equal(t, http.StatusOK, status, string(raw))
	require.Contains(t, string(raw), "backup_codes", "the first second step comes with its codes")

	_, page = laptop.get("/account/security?done=passkey")
	require.Contains(t, page, "Passkey or security key added.")
	require.Contains(t, page, "iPhone")
	require.Contains(t, page, "10 of 10")

	// --- "Confirm it's you" once the second step is old ------------------------
	env.clock.Advance(5 * time.Minute)
	_, _ = laptop.get("/account")
	env.clock.Advance(6 * time.Minute)
	resp, page = laptop.get("/account/security/totp")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `id="title">Confirm it's you</h1>`)
	require.Contains(t, page, `data-mode="stepup"`)
	require.Contains(t, page, "Back to your account")
	resp, _ = laptop.post("/account/security/backup-codes", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "/r/acme/account/security/backup-codes", resp.Header.Get("Location"), "back to the page that asks")

	status, options = laptop.api(http.MethodPost, "/auth/step-up/webauthn/options", map[string]string{})
	require.Equal(t, http.StatusOK, status, string(options))
	assertion, err := key.Get(options)
	require.NoError(t, err)
	status, raw = laptop.api(http.MethodPost, "/auth/step-up/webauthn/verify", json.RawMessage(assertion))
	require.Equal(t, http.StatusOK, status, string(raw))
	// Back to the real time: the database stamps new rows (the pending
	// authenticator app below) with the real clock.
	env.clock.Reset()

	// --- authenticator app, with htmx ------------------------------------------
	_, page = laptop.get("/account/security/totp")
	require.Contains(t, page, `id="totp-start"`)
	resp, page = laptop.post("/account/security/totp", url.Values{"name": {"Pixel"}, "csrf": {csrf}}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `src="data:image/png;base64,`)
	secret := strings.ReplaceAll(regexp.MustCompile(`id="totp-secret">([A-Z2-7 ]+)<`).FindStringSubmatch(page)[1], " ", "")
	totpID := regexp.MustCompile(`/security/totp/([0-9a-f-]{36})/confirm`).FindStringSubmatch(page)[1]

	resp, page = laptop.post("/account/security/totp/"+totpID+"/confirm", url.Values{"code": {"000000"}, "csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, strings.HasPrefix(page, `<div id="totp-code-area"`), page)
	require.Contains(t, page, "This code is not right.")

	resp, _ = laptop.post("/account/security/totp/"+totpID+"/confirm", url.Values{"code": {env.code(t, secret)}, "csrf": {csrf}}, htmx)
	require.Equal(t, "/r/acme/account/security", resp.Header.Get("Hx-Redirect"), "not the first second step: no new codes")
	_, page = laptop.get("/account/security")
	require.Contains(t, page, "Authenticator app added.")
	require.Contains(t, page, "Pixel")

	// --- remove it -------------------------------------------------------------
	resp, page = laptop.get("/account/security/factors/" + totpID + "/remove")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `id="remove-confirm"`)
	resp, _ = laptop.post("/account/security/factors/"+totpID+"/remove", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = laptop.get("/account/security")
	require.Contains(t, page, "Removed.")
	require.NotContains(t, page, "Pixel")

	// --- password: other sessions end, this one stays --------------------------
	tablet := env.newTab(t, "acme")
	tablet.login("alice", pw) // alice has a passkey now: the second step follows
	status, options = tablet.api(http.MethodPost, "/auth/mfa/webauthn/options", map[string]string{})
	require.Equal(t, http.StatusOK, status, string(options))
	assertion, err = key.Get(options)
	require.NoError(t, err)
	status, raw = tablet.api(http.MethodPost, "/auth/mfa/webauthn/verify", json.RawMessage(assertion))
	require.Equal(t, http.StatusOK, status, string(raw))
	status, _ = tablet.sessionID()
	require.Equal(t, http.StatusOK, status)
	resp, page = laptop.get("/account/security/password")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "signs you out of all your other sessions")
	require.Contains(t, page, `minlength="12"`)
	form := func(current, next, confirm string) url.Values {
		return url.Values{"current": {current}, "new": {next}, "confirm": {confirm}, "csrf": {csrf}}
	}
	const newPw = "a-brand-new-passphrase-2026"
	resp, page = laptop.post("/account/security/password", form("wrong-password", newPw, newPw), nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	require.Contains(t, page, "Your current password is not right.")
	resp, page = laptop.post("/account/security/password", form(pw, newPw, newPw+"x"), nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	require.Contains(t, page, "not the same")
	resp, page = laptop.post("/account/security/password", form(pw, "short", "short"), nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	require.Contains(t, page, "at least 12 characters")
	resp, _ = laptop.post("/account/security/password", form(pw, newPw, newPw), nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = laptop.get("/account/security")
	require.Contains(t, page, "Your other sessions were signed out (1).")
	status, _ = tablet.sessionID()
	require.Equal(t, http.StatusUnauthorized, status)
	status, _ = laptop.sessionID()
	require.Equal(t, http.StatusOK, status, "this session stays")
	status, _ = env.newTab(t, "acme").api(http.MethodPost, "/auth/login", map[string]string{"identifier": "alice", "password": pw})
	require.Equal(t, http.StatusUnauthorized, status, "the old password no longer works")

	// --- connected apps --------------------------------------------------------
	payroll, err := env.clients.Create(ctx, repository.CreateClientAppParams{RealmID: acme.ID, Name: "Payroll", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)
	betaApp, err := env.clients.Create(ctx, repository.CreateClientAppParams{RealmID: beta.ID, Name: "Beta Wiki", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)
	_, err = env.consents.Create(ctx, repository.CreateConsentParams{UserID: alice.ID, ClientRefID: payroll.ID, Scopes: []string{"openid", "email"}})
	require.NoError(t, err)
	_, page = laptop.get("/account/apps")
	require.Contains(t, page, "Payroll")
	require.Contains(t, page, "Your e-mail address")
	resp, page = laptop.post("/account/apps/"+betaApp.ID+"/revoke", url.Values{"csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "That item no longer exists.", "another realm's application")
	resp, page = laptop.post("/account/apps/"+payroll.ID+"/revoke", url.Values{"csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "Access removed.")
	require.NotContains(t, page, "Payroll")
	c, err := env.consents.GetByUserAndClient(ctx, alice.ID, payroll.ID)
	require.NoError(t, err)
	require.False(t, c.IsGranted())

	// --- history ---------------------------------------------------------------
	_, page = laptop.get("/account/history")
	require.Contains(t, page, "Signed in")
	_, page = laptop.get("/account/history?view=activity")
	for _, want := range []string{"Name changed", "A session was signed out", "Added a passkey", "Added an authenticator app",
		"Removed an authenticator app", "Password changed", "Access removed for Payroll"} {
		require.Contains(t, page, want)
	}

	// --- organizations: one session per realm ----------------------------------
	resp, page = laptop.get("/r/beta/account")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `id="password-form"`, "no session in beta: its sign-in page")
	resp, _ = laptop.post("/r/beta/account/profile", url.Values{"given_name": {"X"}, "csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "acme's session does nothing in beta")
	status, _ = laptop.api(http.MethodPost, "/r/beta/auth/login", map[string]string{"identifier": "carol", "password": pw})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "beta.acme", laptop.cookie("/r/acme/account", "sso_realms"))
	_, page = laptop.get("/account")
	require.Contains(t, page, `href="/r/beta/account"`)
	require.Contains(t, page, "Beta Labs")
	_, page = laptop.get("/r/beta/account")
	require.Contains(t, page, "carol@example.test")
	require.NotContains(t, page, "alice@example.test")
	resp, _ = laptop.post("/r/beta/account/profile", url.Values{"given_name": {"X"}, "csrf": {csrf}}, nil)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "acme's token is not beta's")

	// --- sign out ----------------------------------------------------------------
	resp, _ = laptop.post("/account/signout", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	status, _ = laptop.sessionID()
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "beta", laptop.cookie("/r/acme/account", "sso_realms"))
	_, page = laptop.get("/account")
	require.Contains(t, page, `id="password-form"`)
}

// An account without a second step: "Confirm it's you" is a new sign-in;
// then its first second step (codes shown at once, htmx), new codes, a
// trusted device, and removing the last second step.
func TestAccountConsole_FirstFactor_Integration(t *testing.T) {
	env := setupAccountTestEnv(t)
	ctx := context.Background()

	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "acme", DisplayName: "Acme Corp"})
	require.NoError(t, err)
	const pw = "correct-horse-battery-staple"
	hash, err := service.HashPassword(pw)
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "bob", Email: "bob@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)

	b := env.newTab(t, "acme")
	b.login("bob", pw)
	_, page := b.get("/account/security")
	require.Contains(t, page, "No second step yet.")
	oldCSRF := csrfOf(t, page)

	// An old sign-in: sign in again first, except to change the password
	// (that form asks for the current one anyway).
	env.clock.Advance(5 * time.Minute)
	_, _ = b.get("/account")
	env.clock.Advance(6 * time.Minute)
	resp, page := b.get("/account/security/totp")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `data-mode="login"`)
	require.Contains(t, page, "enter your password again")
	require.Contains(t, page, `value="bob"`)
	resp, page = b.get("/account/security/password")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `id="password-form"`)
	require.Contains(t, page, `name="current"`)

	env.clock.Reset()
	b.login("bob", pw)
	resp, _ = b.post("/account/profile", url.Values{"given_name": {"Bob"}, "csrf": {oldCSRF}}, nil)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "a new session, a new token")
	_, page = b.get("/account/security/totp")
	csrf := csrfOf(t, page)
	require.NotEqual(t, oldCSRF, csrf)

	// --- first second step: the codes replace the page content (htmx) ---------
	_, page = b.post("/account/security/totp", url.Values{"name": {""}, "csrf": {csrf}}, nil)
	secret := strings.ReplaceAll(regexp.MustCompile(`id="totp-secret">([A-Z2-7 ]+)<`).FindStringSubmatch(page)[1], " ", "")
	totpID := regexp.MustCompile(`/security/totp/([0-9a-f-]{36})/confirm`).FindStringSubmatch(page)[1]
	resp, page = b.post("/account/security/totp/"+totpID+"/confirm", url.Values{"code": {env.code(t, secret)}, "csrf": {csrf}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "#main", resp.Header.Get("Hx-Retarget"))
	require.Equal(t, "innerHTML", resp.Header.Get("Hx-Reswap"))
	require.NotContains(t, page, "<!doctype html>", "only the inside of <main>")
	require.Contains(t, page, "Your account now has two-step verification.")
	firstCodes := regexp.MustCompile(`<li>([^<]+)</li>`).FindAllStringSubmatch(page, -1)
	require.Len(t, firstCodes, 10)

	// --- new codes ---------------------------------------------------------------
	_, page = b.get("/account/security/backup-codes")
	require.Contains(t, page, `id="codes-generate"`)
	resp, page = b.post("/account/security/backup-codes", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	newCodes := regexp.MustCompile(`<li>([^<]+)</li>`).FindAllStringSubmatch(page, -1)
	require.Len(t, newCodes, 10)
	require.NotEqual(t, firstCodes[0][1], newCodes[0][1])

	// --- a device that skips the second step ----------------------------------
	desk := env.newTab(t, "acme")
	desk.login("bob", pw)
	env.clock.Advance(30 * time.Second) // the next code: the first one was used
	status, raw := desk.api(http.MethodPost, "/auth/mfa/verify", map[string]any{"method": "totp", "code": env.code(t, secret), "trust_device": true})
	require.Equal(t, http.StatusOK, status, string(raw))
	require.Contains(t, string(raw), `"device_trusted":true`)
	env.clock.Reset()

	_, page = desk.get("/account/security")
	require.Contains(t, page, "This device")
	deskCSRF := csrfOf(t, page)
	deviceID := regexp.MustCompile(`/security/devices/([0-9a-f-]{36})/revoke`).FindStringSubmatch(page)[1]
	resp, page = desk.post("/account/security/devices/"+deviceID+"/revoke", url.Values{"csrf": {deskCSRF}}, htmx)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, strings.HasPrefix(page, `<section class="card" aria-labelledby="devices-title" id="devices">`), page)
	require.Contains(t, page, "None.")
	require.Contains(t, page, "That device will ask for the second step again.")

	// --- remove the last second step ------------------------------------------
	_, page = b.get("/account/security/factors/" + totpID + "/remove")
	require.Contains(t, page, "It is your last second step")
	resp, _ = b.post("/account/security/factors/"+totpID+"/remove", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = b.get("/account/security")
	require.Contains(t, page, "Removed.")
	require.Contains(t, page, "No second step yet.")

	resp, _ = b.get("/account/security/factors/" + totpID + "/remove")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, "gone: back to Security")
}
