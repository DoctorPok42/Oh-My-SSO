package httpserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	jose "github.com/go-jose/go-jose/v4"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent"
	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 10 Definition of Done, end to end with a real OIDC client
// (golang.org/x/oauth2), a real Postgres and a real Valkey (testcontainers,
// Docker required): authorization code + PKCE + refresh, plus the security
// cases (refresh replay, code replay, missing PKCE, other browser, logout,
// revocation, introspection).

const (
	oidcRealm      = "acme"
	oidcPassword   = "correct-horse-battery-staple"
	webClientID    = "webapp"
	spaClientID    = "spa"
	webRedirectURI = "https://app.example.test/callback"
	spaRedirectURI = "http://127.0.0.1:5173/callback"
	webLogoutURI   = "https://app.example.test/signed-out"

	payrollClientID    = "payroll"
	payrollRedirectURI = "https://payroll.example.test/callback"
)

type discoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	GrantTypes            []string `json:"grant_types_supported"`
	ResponseTypes         []string `json:"response_types_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	IDTokenAlgs           []string `json:"id_token_signing_alg_values_supported"`
}

type oidcTestEnv struct {
	ts        *httptest.Server
	ent       *ent.Client
	realm     *domain.Realm
	realmURL  string
	disc      discoveryDoc
	webSecret string
	// payrollSecret: a client whose MFA policy is "required".
	payrollSecret string
	alice         *domain.User
	tokens        repository.TokenRepository
	audit         repository.AuditLogRepository
	clock         *fakeClock
}

func setupOIDCTestEnv(t *testing.T) *oidcTestEnv {
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

	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	clients := entstore.NewClientRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	attempts := entstore.NewLoginAttemptRepository(client)
	audit := entstore.NewAuditLogRepository(client)
	tokens := entstore.NewTokenRepository(client)
	signingKeys := entstore.NewSigningKeyRepository(client)
	access := entstore.NewAccessRepository(client)
	limiter := valkeycache.NewRateLimiter(valkeyClient)
	km := localdev.New("test")
	clock := &fakeClock{} // moved forward to get the next TOTP code

	sessions := service.NewSessionService(entstore.NewSessionRepository(client), settings, tokens,
		valkeycache.NewSessionCache(valkeyClient), service.WithClock(clock.Now))
	policy := service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: settings, Clients: clients, Roles: entstore.NewRoleRepository(client),
		Policies: entstore.NewMfaPolicyRepository(client), Access: access, Audit: audit, Now: clock.Now,
	})
	mfa := service.NewMFAService(service.MFADeps{
		Users: users, Methods: entstore.NewMfaMethodRepository(client), BackupCodes: entstore.NewMfaBackupCodeRepository(client),
		Sessions: sessions, Policy: policy, Envelope: service.NewEnvelopeService(signingKeys, km, "local_dev"),
		Store: valkeycache.NewMFAStore(valkeyClient), Limiter: limiter, LoginAttempts: attempts, Audit: audit,
		Realms: realms, Clients: clients, Now: clock.Now,
	})
	auth := service.NewAuthService(users, attempts)
	rbac := service.NewRBACService(access, audit)
	idp := service.NewIdentityCore(service.IdentityCoreDeps{
		Auth: auth, Sessions: sessions, RBAC: rbac, Users: users, Clients: clients, Realms: realms,
		Tokens: tokens, SigningKeys: signingKeys, KeyManager: km, MFA: mfa, Audit: audit,
	}, service.WithIdentityCoreClock(clock.Now))

	// The issuer must be the server's own URL, known once it listens.
	var router http.Handler
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	adapter, err := oidcadapter.New(oidcadapter.Config{
		PublicURL:         ts.URL,
		SessionCookieName: httpserver.SessionCookieName,
		Now:               clock.Now,
	}, idp, valkeycache.NewOIDCStore(valkeyClient))
	require.NoError(t, err)
	router = httpserver.New(auth, sessions, rbac, realms, clients, limiter,
		httpserver.WithMFA(mfa), httpserver.WithJWKS(idp), httpserver.WithOIDC(adapter)).Router()

	// --- data: a realm, its signing key, alice (allowed), bob (not) ---
	realm, err := realms.Create(ctx, repository.CreateRealmParams{Name: oidcRealm, DisplayName: "Acme Corp"})
	require.NoError(t, err)
	rotation := service.NewKeyRotationService(signingKeys, entstore.NewKeyRotationLogRepository(client), settings, km, "local_dev")
	_, err = rotation.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test"})
	require.NoError(t, err)

	hash, err := service.HashPassword(oidcPassword)
	require.NoError(t, err)
	alice, err := users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "alice",
		Email: "alice@acme.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	_, err = users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "bob",
		Email: "bob@acme.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)

	employees, err := entstore.NewRoleRepository(client).Create(ctx, repository.CreateRoleParams{RealmID: realm.ID, Name: "employees"})
	require.NoError(t, err)
	admins, err := entstore.NewGroupRepository(client).Create(ctx, repository.CreateGroupParams{RealmID: realm.ID, Name: "admins"})
	require.NoError(t, err)
	require.NoError(t, client.User.UpdateOneID(alice.ID).
		AddRoleIDs(employees.ID).AddGroupIDs(admins.ID).
		SetProfile(map[string]interface{}{"given_name": "Alice", "family_name": "Martin", "email_verified": true}).
		Exec(ctx))

	// A custom scope "groups" (the ArgoCD example of the data model),
	// granted to the employees role.
	scopes := entstore.NewClientScopeRepository(client)
	groups, err := scopes.Create(ctx, repository.CreateClientScopeParams{RealmID: realm.ID, Name: "groups"})
	require.NoError(t, err)
	_, err = scopes.Update(ctx, groups.ID, repository.UpdateClientScopeParams{ClaimMappers: []map[string]interface{}{
		{"source_attribute": "groups", "claim_name": "groups", "token_location": []string{"id_token", "userinfo", "access_token"}},
		{"source_attribute": "username", "claim_name": "sub"}, // reserved: must be ignored
	}})
	require.NoError(t, err)
	require.NoError(t, client.Role.UpdateOneID(employees.ID).AddClientScopeIDs(groups.ID).Exec(ctx))

	oidcClients := service.NewOIDCClientService(clients, scopes, entstore.NewRoleRepository(client), entstore.NewGroupRepository(client))
	web, webSecret, err := oidcClients.Create(ctx, service.OIDCClientInput{
		RealmID: realm.ID, Name: "Web App", ClientID: webClientID,
		RedirectURIs: []string{webRedirectURI}, PostLogoutRedirectURIs: []string{webLogoutURI},
		Scopes:     []string{"profile", "email", "offline_access", "groups"},
		AllowRoles: []string{"employees"},
	})
	require.NoError(t, err)
	_, err = clients.Update(ctx, web.ID, repository.UpdateClientAppParams{
		AttributeMappings: map[string]interface{}{"email": "mail", "preferred_username": "sub"}, // 2nd: reserved, ignored
	})
	require.NoError(t, err)
	_, _, err = oidcClients.Create(ctx, service.OIDCClientInput{
		RealmID: realm.ID, Name: "Single Page App", ClientID: spaClientID, Public: true,
		RedirectURIs: []string{spaRedirectURI}, Scopes: []string{"profile", "offline_access"},
		AllowRoles: []string{"employees"},
	})
	require.NoError(t, err)
	// payroll requires a second factor (Step 9 client policy).
	payroll, payrollSecret, err := oidcClients.Create(ctx, service.OIDCClientInput{
		RealmID: realm.ID, Name: "Payroll", ClientID: payrollClientID,
		RedirectURIs: []string{payrollRedirectURI}, AllowRoles: []string{"employees"},
	})
	require.NoError(t, err)
	required := domain.ClientAppMFARequired
	_, err = clients.Update(ctx, payroll.ID, repository.UpdateClientAppParams{MFAPolicy: &required})
	require.NoError(t, err)

	env := &oidcTestEnv{ts: ts, ent: client, realm: realm, realmURL: ts.URL + "/r/" + oidcRealm,
		webSecret: webSecret, payrollSecret: payrollSecret, alice: alice, tokens: tokens, audit: audit, clock: clock}
	resp, err := ts.Client().Get(env.realmURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env.disc))
	return env
}

// --- a browser and an OAuth client ---------------------------------------------

type oidcBrowser struct {
	t  *testing.T
	c  *http.Client
	ts *httptest.Server
}

// newBrowser: its own cookie jar; it follows redirects inside the IdP and
// stops at the first one leaving it (the application's redirect_uri).
func (e *oidcTestEnv) newBrowser(t *testing.T) *oidcBrowser {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{
		Transport: e.ts.Client().Transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if !strings.HasPrefix(req.URL.String(), e.ts.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &oidcBrowser{t: t, c: c, ts: e.ts}
}

func (b *oidcBrowser) get(u string) *http.Response {
	b.t.Helper()
	resp, err := b.c.Get(u)
	require.NoError(b.t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (b *oidcBrowser) postJSON(u string, body any) (int, map[string]any) {
	b.t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := b.c.Post(u, "application/json", bytes.NewReader(raw))
	require.NoError(b.t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *oidcTestEnv) oauth(clientID, secret, redirect string, scopes ...string) *oauth2.Config {
	style := oauth2.AuthStyleInHeader
	if secret == "" {
		style = oauth2.AuthStyleInParams // public client: client_id in the body, no secret
	}
	return &oauth2.Config{
		ClientID: clientID, ClientSecret: secret, RedirectURL: redirect,
		Scopes:   append([]string{"openid"}, scopes...),
		Endpoint: oauth2.Endpoint{AuthURL: e.disc.AuthorizationEndpoint, TokenURL: e.disc.TokenEndpoint, AuthStyle: style},
	}
}

// ctx makes x/oauth2 use the test server's TLS client.
func (e *oidcTestEnv) ctx() context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, e.ts.Client())
}

func randomString(t *testing.T) string {
	t.Helper()
	return rand.Text()
}

// loginAndGetCode runs the browser part of the flow: /authorize, the login
// page, the JSON login (what login.js does), the callback. It returns the
// code from the redirect to the application.
func (e *oidcTestEnv) loginAndGetCode(t *testing.T, b *oidcBrowser, cfg *oauth2.Config, user string, opts ...oauth2.AuthCodeOption) string {
	t.Helper()
	state := randomString(t)
	resp := b.get(cfg.AuthCodeURL(state, opts...))
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected the login page")
	loginURL := resp.Request.URL.String()
	require.Contains(t, loginURL, "/r/"+oidcRealm+"/oidc/login?id=")

	status, body := b.postJSON(e.realmURL+"/auth/login", map[string]any{
		"identifier": user, "password": oidcPassword, "client_id": cfg.ClientID})
	require.Equal(t, http.StatusOK, status, "login: %v", body)
	require.Equal(t, "authenticated", body["status"])

	resp = b.get(loginURL) // what login.js does: reload
	return codeFromRedirect(t, resp, cfg.RedirectURL, state)
}

func codeFromRedirect(t *testing.T, resp *http.Response, redirectURI, state string) string {
	t.Helper()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(loc.String(), redirectURI), "redirected to %s", loc)
	require.Empty(t, loc.Query().Get("error"), "error: %s", loc.Query().Get("error_description"))
	require.Equal(t, state, loc.Query().Get("state"))
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func errorFromRedirect(t *testing.T, resp *http.Response, redirectURI string) string {
	t.Helper()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(loc.String(), redirectURI), "redirected to %s", loc)
	return loc.Query().Get("error")
}

// verifyJWT checks a token's signature against the realm's JWKS and returns
// its claims, like any OIDC client library does.
func (e *oidcTestEnv) verifyJWT(t *testing.T, token string) map[string]any {
	t.Helper()
	resp, err := e.ts.Client().Get(e.disc.JwksURI)
	require.NoError(t, err)
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	require.NoError(t, err)
	keys := set.Key(jws.Signatures[0].Header.KeyID)
	require.Len(t, keys, 1, "kid %q not in the JWKS", jws.Signatures[0].Header.KeyID)
	payload, err := jws.Verify(keys[0])
	require.NoError(t, err, "signature does not verify with the published key")
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func (e *oidcTestEnv) userinfo(t *testing.T, accessToken string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.disc.UserinfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := e.ts.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *oidcTestEnv) refresh(cfg *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	return cfg.TokenSource(e.ctx(), &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-time.Hour)}).Token()
}

func requireInvalidGrant(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var re *oauth2.RetrieveError
	require.ErrorAs(t, err, &re)
	require.Equal(t, "invalid_grant", re.ErrorCode, "body: %s", re.Body)
}

// --- the Definition of Done ------------------------------------------------------

func TestOIDC_Integration_DefinitionOfDone(t *testing.T) {
	e := setupOIDCTestEnv(t)

	t.Run("discovery", func(t *testing.T) {
		require.Equal(t, e.realmURL, e.disc.Issuer)
		require.Equal(t, e.realmURL+"/oidc/authorize", e.disc.AuthorizationEndpoint)
		require.Equal(t, e.realmURL+"/oidc/token", e.disc.TokenEndpoint)
		require.Equal(t, e.realmURL+"/.well-known/jwks.json", e.disc.JwksURI)
		require.Equal(t, []string{"code"}, e.disc.ResponseTypes)
		require.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, e.disc.GrantTypes)
		require.Equal(t, []string{"S256"}, e.disc.CodeChallengeMethods)
		require.Contains(t, e.disc.IDTokenAlgs, "RS256")
	})

	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI, "profile", "email", "offline_access", "groups")
	b := e.newBrowser(t)
	verifier := oauth2.GenerateVerifier()
	nonce := randomString(t)
	code := e.loginAndGetCode(t, b, cfg, "alice", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))

	tok, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	require.NotEmpty(t, tok.AccessToken)
	require.NotEmpty(t, tok.RefreshToken)
	require.WithinDuration(t, time.Now().Add(5*time.Minute), tok.Expiry, time.Minute, "access tokens live 5 minutes")
	rawID, _ := tok.Extra("id_token").(string)
	require.NotEmpty(t, rawID)

	t.Run("id_token", func(t *testing.T) {
		c := e.verifyJWT(t, rawID)
		require.Equal(t, e.realmURL, c["iss"])
		require.Equal(t, e.alice.ID, c["sub"], "public subject = User.ID, never the e-mail")
		require.Equal(t, webClientID, c["azp"])
		require.Equal(t, nonce, c["nonce"])
		require.NotEmpty(t, c["sid"])
		require.NotEmpty(t, c["at_hash"])
		require.Equal(t, []any{"pwd"}, c["amr"])
		require.Equal(t, "alice", c["preferred_username"], "the reserved rename preferred_username->sub was ignored")
		require.Equal(t, "Alice", c["given_name"])
		require.Equal(t, "alice@acme.test", c["mail"], "attribute_mappings renamed email to mail")
		require.NotContains(t, c, "email")
		require.Equal(t, true, c["email_verified"])
		require.Equal(t, []any{"admins"}, c["groups"], "custom scope + claim mapper")
	})

	t.Run("access token is a JWT for APIs", func(t *testing.T) {
		c := e.verifyJWT(t, tok.AccessToken)
		require.Equal(t, e.realmURL, c["iss"])
		require.Equal(t, e.alice.ID, c["sub"])
		require.Equal(t, webClientID, c["client_id"])
		require.Equal(t, "openid profile email offline_access groups", c["scope"])
		require.Equal(t, []any{"admins"}, c["groups"])
		require.NotContains(t, c, "given_name", "profile claims are not for APIs")
		require.NotEmpty(t, c["jti"])
	})

	t.Run("userinfo", func(t *testing.T) {
		status, info := e.userinfo(t, tok.AccessToken)
		require.Equal(t, http.StatusOK, status, "%v", info)
		require.Equal(t, e.alice.ID, info["sub"])
		require.Equal(t, "alice@acme.test", info["mail"])
		require.Equal(t, []any{"admins"}, info["groups"])
	})

	// Refresh: a new pair; the old refresh token is consumed.
	tok2, err := e.refresh(cfg, tok.RefreshToken)
	require.NoError(t, err)
	require.NotEqual(t, tok.RefreshToken, tok2.RefreshToken, "rotation: a new refresh token every time")
	require.NotEqual(t, tok.AccessToken, tok2.AccessToken)
	idAfterRefresh := e.verifyJWT(t, tok2.Extra("id_token").(string))
	require.Equal(t, e.alice.ID, idAfterRefresh["sub"])
	require.NotContains(t, idAfterRefresh, "nonce", "no nonce on a refreshed id_token")
	status, _ := e.userinfo(t, tok2.AccessToken)
	require.Equal(t, http.StatusOK, status)

	tok3, err := e.refresh(cfg, tok2.RefreshToken)
	require.NoError(t, err)

	t.Run("refresh token replay revokes the whole family", func(t *testing.T) {
		_, err := e.refresh(cfg, tok.RefreshToken) // already used
		requireInvalidGrant(t, err)

		_, err = e.refresh(cfg, tok3.RefreshToken) // the newest one dies too
		requireInvalidGrant(t, err)
		status, _ := e.userinfo(t, tok3.AccessToken)
		require.Equal(t, http.StatusForbidden, status, "access tokens of the family are revoked too")

		logs, err := e.audit.ListByRealm(context.Background(), e.realm.ID)
		require.NoError(t, err)
		found := false
		for _, l := range logs {
			if l.Action == "refresh_token_reuse_detected" {
				found = true
				require.Equal(t, domain.AuditLogWarning, l.Level)
				require.Equal(t, e.alice.ID, l.UserID)
			}
		}
		require.True(t, found, "a replay leaves an AuditLog entry")
	})
}

func TestOIDC_Integration_PublicClientPKCE(t *testing.T) {
	e := setupOIDCTestEnv(t)
	cfg := e.oauth(spaClientID, "", spaRedirectURI, "profile", "offline_access")

	t.Run("without code_challenge: refused at /authorize", func(t *testing.T) {
		b := e.newBrowser(t)
		resp := b.get(cfg.AuthCodeURL("s"))
		require.Equal(t, "invalid_request", errorFromRedirect(t, resp, spaRedirectURI))
	})

	t.Run("plain is refused", func(t *testing.T) {
		b := e.newBrowser(t)
		resp := b.get(cfg.AuthCodeURL("s", oauth2.SetAuthURLParam("code_challenge", "abc"),
			oauth2.SetAuthURLParam("code_challenge_method", "plain")))
		require.Equal(t, "invalid_request", errorFromRedirect(t, resp, spaRedirectURI))
	})

	t.Run("wrong verifier: invalid_grant, and the code is burnt", func(t *testing.T) {
		b := e.newBrowser(t)
		verifier := oauth2.GenerateVerifier()
		code := e.loginAndGetCode(t, b, cfg, "alice", oauth2.S256ChallengeOption(verifier))
		_, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(oauth2.GenerateVerifier()))
		requireInvalidGrant(t, err)
		_, err = cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		requireInvalidGrant(t, err)
	})

	t.Run("code + PKCE + refresh without any secret", func(t *testing.T) {
		b := e.newBrowser(t)
		verifier := oauth2.GenerateVerifier()
		code := e.loginAndGetCode(t, b, cfg, "alice", oauth2.S256ChallengeOption(verifier))
		tok, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		require.NoError(t, err)
		tok2, err := e.refresh(cfg, tok.RefreshToken)
		require.NoError(t, err)
		require.NotEqual(t, tok.RefreshToken, tok2.RefreshToken)
	})
}

func TestOIDC_Integration_CodeReplay(t *testing.T) {
	e := setupOIDCTestEnv(t)
	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI, "offline_access")
	b := e.newBrowser(t)
	verifier := oauth2.GenerateVerifier()
	code := e.loginAndGetCode(t, b, cfg, "alice", oauth2.S256ChallengeOption(verifier))

	tok, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	status, _ := e.userinfo(t, tok.AccessToken)
	require.Equal(t, http.StatusOK, status)

	// RFC 6749, section 4.1.2: a code used twice is refused, and the tokens
	// it already gave are revoked.
	_, err = cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
	requireInvalidGrant(t, err)
	status, _ = e.userinfo(t, tok.AccessToken)
	require.Equal(t, http.StatusForbidden, status)
	_, err = e.refresh(cfg, tok.RefreshToken)
	requireInvalidGrant(t, err)
}

func TestOIDC_Integration_LoginRules(t *testing.T) {
	e := setupOIDCTestEnv(t)
	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI)
	pkce := oauth2.S256ChallengeOption(oauth2.GenerateVerifier())

	t.Run("prompt=none without a session: login_required", func(t *testing.T) {
		b := e.newBrowser(t)
		resp := b.get(cfg.AuthCodeURL("s", pkce, oauth2.SetAuthURLParam("prompt", "none")))
		require.Equal(t, "login_required", errorFromRedirect(t, resp, webRedirectURI))
	})

	t.Run("a user without access to the client: access_denied", func(t *testing.T) {
		b := e.newBrowser(t)
		state := "s"
		resp := b.get(cfg.AuthCodeURL(state, pkce))
		loginURL := resp.Request.URL.String()
		status, _ := b.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "bob", "password": oidcPassword})
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "access_denied", errorFromRedirect(t, b.get(loginURL), webRedirectURI))
	})

	t.Run("the login link only works in the browser that started it", func(t *testing.T) {
		attacker := e.newBrowser(t)
		resp := attacker.get(cfg.AuthCodeURL("s", pkce))
		loginURL := resp.Request.URL.String()

		victim := e.newBrowser(t)
		status, _ := victim.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "alice", "password": oidcPassword})
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, http.StatusBadRequest, victim.get(loginURL).StatusCode)
	})

	t.Run("SSO: a second application gets in without a password", func(t *testing.T) {
		b := e.newBrowser(t)
		code := e.loginAndGetCode(t, b, cfg, "alice", pkce)
		require.NotEmpty(t, code)
		spa := e.oauth(spaClientID, "", spaRedirectURI)
		resp := b.get(spa.AuthCodeURL("s2", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
		codeFromRedirect(t, resp, spaRedirectURI, "s2")
	})

	t.Run("unknown redirect_uri: no redirect at all", func(t *testing.T) {
		b := e.newBrowser(t)
		bad := *cfg
		bad.RedirectURL = "https://evil.example/callback"
		resp := b.get(bad.AuthCodeURL("s", pkce))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// prompt=login and max_age, in their own realm: the Step 4 rate limit
// counts every login of an identifier (5 per 15 minutes).
func TestOIDC_Integration_Reauthentication(t *testing.T) {
	e := setupOIDCTestEnv(t)
	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI)
	pkce := oauth2.S256ChallengeOption(oauth2.GenerateVerifier())

	t.Run("prompt=login asks again despite the session, then goes through", func(t *testing.T) {
		b := e.newBrowser(t)
		e.loginAndGetCode(t, b, cfg, "alice", pkce)
		// loginAndGetCode checks the login page shows up, then logs in again.
		e.loginAndGetCode(t, b, cfg, "alice", pkce, oauth2.SetAuthURLParam("prompt", "login"))
	})

	t.Run("max_age", func(t *testing.T) {
		b := e.newBrowser(t)
		e.loginAndGetCode(t, b, cfg, "alice", pkce)
		// A login from a moment ago is fine for max_age=3600...
		resp := b.get(cfg.AuthCodeURL("m1", pkce, oauth2.SetAuthURLParam("max_age", "3600")))
		codeFromRedirect(t, resp, webRedirectURI, "m1")
		// ...but not for max_age=0: password again, and then it works.
		e.loginAndGetCode(t, b, cfg, "alice", pkce, oauth2.SetAuthURLParam("max_age", "0"))
	})

}

func TestOIDC_Integration_LogoutRevocationIntrospection(t *testing.T) {
	e := setupOIDCTestEnv(t)
	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI, "offline_access")
	login := func(t *testing.T, b *oidcBrowser) *oauth2.Token {
		verifier := oauth2.GenerateVerifier()
		code := e.loginAndGetCode(t, b, cfg, "alice", oauth2.S256ChallengeOption(verifier))
		tok, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		require.NoError(t, err)
		return tok
	}
	introspect := func(t *testing.T, token string) map[string]any {
		form := url.Values{"token": {token}}
		req, _ := http.NewRequest(http.MethodPost, e.disc.IntrospectionEndpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(webClientID, e.webSecret)
		resp, err := e.ts.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		out := map[string]any{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		return out
	}

	t.Run("introspection then revocation", func(t *testing.T) {
		tok := login(t, e.newBrowser(t))
		res := introspect(t, tok.AccessToken)
		require.Equal(t, true, res["active"])
		require.Equal(t, e.alice.ID, res["sub"])
		require.Equal(t, webClientID, res["client_id"])

		form := url.Values{"token": {tok.RefreshToken}, "token_type_hint": {"refresh_token"}}
		req, _ := http.NewRequest(http.MethodPost, e.disc.RevocationEndpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(webClientID, e.webSecret)
		resp, err := e.ts.Client().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		_, err = e.refresh(cfg, tok.RefreshToken)
		requireInvalidGrant(t, err)
		require.Equal(t, false, introspect(t, tok.AccessToken)["active"], "revoking the refresh token ends the grant")
	})

	t.Run("RP-initiated logout ends the SSO session", func(t *testing.T) {
		b := e.newBrowser(t)
		tok := login(t, b)
		idToken := tok.Extra("id_token").(string)

		q := url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {webLogoutURI}, "state": {"bye"}}
		resp := b.get(e.disc.EndSessionEndpoint + "?" + q.Encode())
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.Equal(t, webLogoutURI+"?state=bye", resp.Header.Get("Location"))

		_, err := e.refresh(cfg, tok.RefreshToken)
		requireInvalidGrant(t, err)
		// The browser has to log in again.
		resp = b.get(cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, resp.Request.URL.Path, "/oidc/login")
	})

	t.Run("logout without id_token_hint is refused", func(t *testing.T) {
		resp := e.newBrowser(t).get(e.disc.EndSessionEndpoint)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// --- MFA (Step 9) through the OIDC login page -----------------------------------------

func (e *oidcTestEnv) totpCode(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, e.clock.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	return c
}

func (b *oidcBrowser) page(u string) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.c.Get(u)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func TestOIDC_Integration_MFA(t *testing.T) {
	e := setupOIDCTestEnv(t)
	payroll := e.oauth(payrollClientID, e.payrollSecret, payrollRedirectURI)
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)
	pkce := func() oauth2.AuthCodeOption { return oauth2.S256ChallengeOption(oauth2.GenerateVerifier()) }
	login := func(b *oidcBrowser) map[string]any {
		status, body := b.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "alice", "password": oidcPassword, "client_id": payrollClientID})
		require.Equal(t, http.StatusOK, status, "%v", body)
		return body
	}

	// An older session, opened before alice had any factor (for the step-up).
	old := e.newBrowser(t)
	e.loginAndGetCode(t, old, web, "alice", pkce())

	// 1. payroll requires MFA and alice has no factor: the page asks her to
	// enroll one.
	b := e.newBrowser(t)
	resp := b.get(payroll.AuthCodeURL("s1", pkce()))
	loginURL := resp.Request.URL.String()
	require.Equal(t, "mfa_enrollment_required", login(b)["status"])
	resp, body := b.page(loginURL)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, `data-mode="enroll"`)

	// 2. She enrolls a TOTP (Step 9 API, as the account page does)...
	status, out := b.postJSON(e.realmURL+"/account/mfa/totp", map[string]string{"name": "phone"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	secret, methodID := out["secret"].(string), out["method_id"].(string)
	status, out = b.postJSON(e.realmURL+"/account/mfa/totp/"+methodID+"/confirm", map[string]string{"code": e.totpCode(t, secret)})
	require.Equal(t, http.StatusOK, status, "%v", out)
	// ...and the same login request goes through: enrolling verified the session.
	codeFromRedirect(t, b.get(loginURL), payrollRedirectURI, "s1")

	// 3. A new browser: password, then the TOTP challenge. The id_token
	// says how she authenticated (amr).
	e.clock.Advance(30 * time.Second)
	b2 := e.newBrowser(t)
	verifier := oauth2.GenerateVerifier()
	resp = b2.get(payroll.AuthCodeURL("s2", oauth2.S256ChallengeOption(verifier)))
	loginURL = resp.Request.URL.String()
	first := login(b2)
	// login.js shows the code form right away (no full session yet: the
	// pending MFA state lives in its own cookie, Step 9).
	require.Equal(t, "mfa_required", first["status"])
	status, out = b2.postJSON(e.realmURL+"/auth/mfa/verify", map[string]string{"method": "totp", "code": e.totpCode(t, secret)})
	require.Equal(t, http.StatusOK, status, "%v", out)
	code := codeFromRedirect(t, b2.get(loginURL), payrollRedirectURI, "s2")
	tok, err := payroll.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	idToken := e.verifyJWT(t, tok.Extra("id_token").(string))
	require.Contains(t, idToken["amr"], "pwd")
	require.Contains(t, idToken["amr"], "otp")
	require.Contains(t, idToken["amr"], "mfa")

	// 4. Step-up: the old session never verified a factor. payroll asks for
	// one in that same session (no new password).
	e.clock.Advance(30 * time.Second)
	resp, body = old.page(payroll.AuthCodeURL("s3", pkce()))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, `data-mode="stepup"`)
	loginURL = resp.Request.URL.String()
	// prompt=none cannot show that page: interaction_required.
	require.Equal(t, "interaction_required",
		errorFromRedirect(t, old.get(payroll.AuthCodeURL("s4", pkce(), oauth2.SetAuthURLParam("prompt", "none"))), payrollRedirectURI))
	status, out = old.postJSON(e.realmURL+"/auth/step-up", map[string]string{"method": "totp", "code": e.totpCode(t, secret)})
	require.Equal(t, http.StatusOK, status, "%v", out)
	codeFromRedirect(t, old.get(loginURL), payrollRedirectURI, "s3")
}
