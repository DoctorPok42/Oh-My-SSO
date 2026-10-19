package httpserver_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"math/big"
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
	"github.com/beevik/etree"
	samllib "github.com/crewjam/saml"
	_ "github.com/jackc/pgx/v5/stdlib"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	samladapter "sso.internal/sso/internal/adapters/saml"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 11, end to end with real service providers (crewjam/saml's
// ServiceProvider, an independent implementation of the SP side: it checks
// our signatures, audience, recipient, InResponseTo and dates), a real
// Postgres and a real Valkey: SSO with both bindings, the security cases,
// key rotation and Single Logout across several providers.
//
// The SimpleSAMLphp run of the Definition of Done is described in the
// Step 11 notes; this test is what runs on every build.

const (
	samlRealm    = "acme"
	samlPassword = "correct-horse-battery-staple"
)

type samlTestEnv struct {
	ts       *httptest.Server
	ent      *ent.Client
	realm    *domain.Realm
	realmURL string
	rotation *service.KeyRotationService
	tokens   repository.TokenRepository
	clients  repository.ClientRepository
	samlSvc  *service.SAMLClientService
	alice    *domain.User
}

func setupSAMLTestEnv(t *testing.T) *samlTestEnv {
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

	sessions := service.NewSessionService(entstore.NewSessionRepository(client), settings, tokens,
		valkeycache.NewSessionCache(valkeyClient))
	policy := service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: settings, Clients: clients, Roles: entstore.NewRoleRepository(client),
		Policies: entstore.NewMfaPolicyRepository(client), Access: access, Audit: audit,
	})
	mfa := service.NewMFAService(service.MFADeps{
		Users: users, Methods: entstore.NewMfaMethodRepository(client), BackupCodes: entstore.NewMfaBackupCodeRepository(client),
		Sessions: sessions, Policy: policy, Envelope: service.NewEnvelopeService(signingKeys, km, "local_dev"),
		Store: valkeycache.NewMFAStore(valkeyClient), Limiter: limiter, LoginAttempts: attempts, Audit: audit,
		Realms: realms, Clients: clients,
	})
	auth := service.NewAuthService(users, attempts)
	rbac := service.NewRBACService(access, audit)
	idp := service.NewIdentityCore(service.IdentityCoreDeps{
		Auth: auth, Sessions: sessions, RBAC: rbac, Users: users, Clients: clients, Realms: realms,
		Tokens: tokens, SigningKeys: signingKeys, KeyManager: km, MFA: mfa, Audit: audit,
	})

	var router http.Handler
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	store := valkeycache.NewOIDCStore(valkeyClient)
	oidcA, err := oidcadapter.New(oidcadapter.Config{PublicURL: ts.URL, SessionCookieName: httpserver.SessionCookieName}, idp, store)
	require.NoError(t, err)
	samlA, err := samladapter.New(samladapter.Config{PublicURL: ts.URL, SessionCookieName: httpserver.SessionCookieName}, idp, store)
	require.NoError(t, err)
	router = httpserver.New(auth, sessions, rbac, realms, clients, limiter,
		httpserver.WithMFA(mfa), httpserver.WithJWKS(idp), httpserver.WithOIDC(oidcA), httpserver.WithSAML(samlA)).Router()

	realm, err := realms.Create(ctx, repository.CreateRealmParams{Name: samlRealm, DisplayName: "Acme Corp"})
	require.NoError(t, err)
	rotation := service.NewKeyRotationService(signingKeys, entstore.NewKeyRotationLogRepository(client), settings, km, "local_dev")
	_, err = rotation.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test"}) // JWT, for OIDC
	require.NoError(t, err)
	_, err = rotation.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test", Purpose: domain.SigningKeyPurposeSAMLSigning})
	require.NoError(t, err)

	hash, err := service.HashPassword(samlPassword)
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
	require.NoError(t, client.User.UpdateOneID(alice.ID).AddRoleIDs(employees.ID).AddGroupIDs(admins.ID).
		SetProfile(map[string]interface{}{"given_name": "Alice", "family_name": "Martin"}).Exec(ctx))

	// The attribute scope of the demo seed, granted to the employees.
	scopes := entstore.NewClientScopeRepository(client)
	sc, err := scopes.Create(ctx, repository.CreateClientScopeParams{RealmID: realm.ID, Name: "saml_profile"})
	require.NoError(t, err)
	saml2 := domain.ClientScopeProtocolSAML2
	_, err = scopes.Update(ctx, sc.ID, repository.UpdateClientScopeParams{Protocol: &saml2, ClaimMappers: []map[string]interface{}{
		{"source_attribute": "username", "claim_name": "uid"},
		{"source_attribute": "email", "claim_name": "mail"},
		{"source_attribute": "profile.given_name", "claim_name": "givenName"},
		{"source_attribute": "groups", "claim_name": "groups"},
	}})
	require.NoError(t, err)
	require.NoError(t, client.Role.UpdateOneID(employees.ID).AddClientScopeIDs(sc.ID).Exec(ctx))

	return &samlTestEnv{
		ts: ts, ent: client, realm: realm, realmURL: ts.URL + "/r/" + samlRealm, rotation: rotation,
		tokens: tokens, clients: clients, alice: alice,
		samlSvc: service.NewSAMLClientService(clients, scopes, entstore.NewRoleRepository(client), entstore.NewGroupRepository(client)),
	}
}

// --- the IdP as a service provider sees it ---------------------------------------------

func (e *samlTestEnv) metadata(t *testing.T) *samllib.EntityDescriptor {
	t.Helper()
	resp, err := e.ts.Client().Get(e.realmURL + "/saml/metadata")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/samlmetadata+xml", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	var ed samllib.EntityDescriptor
	require.NoError(t, xml.Unmarshal(body, &ed))
	return &ed
}

func idpCerts(t *testing.T, md *samllib.EntityDescriptor) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, kd := range md.IDPSSODescriptors[0].KeyDescriptors {
		require.Equal(t, "signing", kd.Use)
		der, err := base64.StdEncoding.DecodeString(kd.KeyInfo.X509Data.X509Certificates[0].Data)
		require.NoError(t, err)
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		out = append(out, c)
	}
	return out
}

// --- service providers ------------------------------------------------------------------

type testSP struct {
	t      *testing.T
	env    *samlTestEnv
	sp     *samllib.ServiceProvider
	key    *rsa.PrivateKey
	cert   *x509.Certificate
	format string
}

type spOpts struct {
	name       string
	signed     bool // registers a certificate: it must then sign everything
	slo        bool
	nameID     string
	allow      bool // grant the employees role
	mutateApp  func(*repository.UpdateClientAppParams)
	wantResign bool
}

func (e *samlTestEnv) newSP(t *testing.T, o spOpts) *testSP {
	t.Helper()
	base := "https://" + o.name + ".example.test"
	in := service.SAMLClientInput{
		RealmID: e.realm.ID, Name: o.name, EntityID: base + "/metadata", ACSURL: base + "/acs",
		NameIDFormat: o.nameID, Scopes: []string{"saml_profile"}, WantResponseSigned: o.wantResign,
		AttributeMappings: map[string]string{"givenName": "firstName"},
	}
	if o.slo {
		in.SLOURL = base + "/slo"
	}
	if o.allow {
		in.AllowRoles = []string{"employees"}
	}
	s := &testSP{t: t, env: e}
	if o.signed {
		s.key, s.cert = rsaCert(t)
		in.Certificates = []domain.ClientCertificate{{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Raw}))}}
	}
	app, err := e.samlSvc.Create(context.Background(), in)
	require.NoError(t, err)
	s.format = app.NameIDFormat
	if o.mutateApp != nil {
		var upd repository.UpdateClientAppParams
		o.mutateApp(&upd)
		_, err := e.clients.Update(context.Background(), app.ID, upd)
		require.NoError(t, err)
	}
	s.sp = &samllib.ServiceProvider{
		EntityID: in.EntityID, AcsURL: mustParseURL(t, in.ACSURL), IDPMetadata: e.metadata(t),
		AuthnNameIDFormat: samllib.UnspecifiedNameIDFormat,
	}
	if in.SLOURL != "" {
		s.sp.SloURL = mustParseURL(t, in.SLOURL)
	}
	if o.signed {
		s.sp.Key, s.sp.Certificate, s.sp.SignatureMethod = s.key, s.cert, dsig.RSASHA256SignatureMethod
	}
	return s
}

func rsaCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func mustParseURL(t *testing.T, s string) url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return *u
}

// redirectRequest: an AuthnRequest with the HTTP-Redirect binding (signed
// in the query string by crewjam when the SP has a key).
func (s *testSP) redirectRequest(mod func(*samllib.AuthnRequest)) (string, string) {
	s.t.Helper()
	req, err := s.sp.MakeAuthenticationRequest(s.env.realmURL+"/saml/sso", samllib.HTTPRedirectBinding, samllib.HTTPPostBinding)
	require.NoError(s.t, err)
	if mod != nil {
		mod(req)
	}
	u, err := req.Redirect("relay-123", s.sp)
	require.NoError(s.t, err)
	return u.String(), req.ID
}

// postRequest: an AuthnRequest with the HTTP-POST binding (XML signature).
func (s *testSP) postRequest(mod func(*samllib.AuthnRequest)) (url.Values, string) {
	s.t.Helper()
	req, err := s.sp.MakeAuthenticationRequest(s.env.realmURL+"/saml/sso", samllib.HTTPPostBinding, samllib.HTTPPostBinding)
	require.NoError(s.t, err)
	if mod != nil {
		mod(req)
		if s.sp.SignatureMethod != "" {
			req.Signature = nil
			require.NoError(s.t, s.sp.SignAuthnRequest(req))
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	b, err := doc.WriteToBytes()
	require.NoError(s.t, err)
	return url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(b)}, "RelayState": {"post-relay"}}, req.ID
}

// assertion checks a response like a real SP (crewjam does the work).
func (s *testSP) assertion(samlResponse, requestID string) (*samllib.Assertion, error) {
	s.t.Helper()
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	require.NoError(s.t, err)
	return s.sp.ParseXMLResponse(raw, []string{requestID}, s.sp.AcsURL)
}

// --- the browser ---------------------------------------------------------------------------

type samlBrowser struct {
	t   *testing.T
	c   *http.Client
	env *samlTestEnv
}

func (e *samlTestEnv) browser(t *testing.T) *samlBrowser {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &samlBrowser{t: t, env: e, c: &http.Client{
		Transport: e.ts.Client().Transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if !strings.HasPrefix(req.URL.String(), e.ts.URL) {
				return http.ErrUseLastResponse // leaves the IdP: a service provider
			}
			return nil
		},
	}}
}

func (b *samlBrowser) do(req *http.Request) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.c.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (b *samlBrowser) get(u string) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return b.do(req)
}

func (b *samlBrowser) postForm(u string, form url.Values) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

func (b *samlBrowser) login(identifier string) {
	b.t.Helper()
	body := `{"identifier":"` + identifier + `","password":"` + samlPassword + `"}`
	req, _ := http.NewRequest(http.MethodPost, b.env.realmURL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := b.do(req)
	require.Equal(b.t, http.StatusOK, resp.StatusCode)
}

var (
	reAction = regexp.MustCompile(`<form id="autopost" method="post" action="([^"]*)"`)
	reField  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
)

// autoPost reads the self-submitting form of a response page.
func autoPost(t *testing.T, body string) (string, map[string]string) {
	t.Helper()
	m := reAction.FindStringSubmatch(body)
	require.NotNil(t, m, "auto-post form expected, got: %.300s", body)
	fields := map[string]string{}
	for _, f := range reField.FindAllStringSubmatch(body, -1) {
		fields[f[1]] = html.UnescapeString(f[2])
	}
	return html.UnescapeString(m[1]), fields
}

// signIn: from the AuthnRequest to the response page, logging in on the way.
func (b *samlBrowser) signIn(start func() (*http.Response, string), user string) (string, map[string]string) {
	b.t.Helper()
	resp, body := start()
	require.Equal(b.t, http.StatusOK, resp.StatusCode, body)
	if strings.Contains(body, `id="password-form"`) && !strings.Contains(body, `<form id="password-form" hidden`) {
		require.Contains(b.t, body, `data-client-param="entity_id"`)
		b.login(user)
		resp, body = b.get(resp.Request.URL.String()) // the page reloads itself
		require.Equal(b.t, http.StatusOK, resp.StatusCode, body)
	}
	return autoPost(b.t, body)
}

// statusOf reads the status of a response without assertion.
func statusOf(t *testing.T, samlResponse string) (string, string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	require.NoError(t, err)
	var resp samllib.Response
	require.NoError(t, xml.Unmarshal(raw, &resp))
	second := ""
	if resp.Status.StatusCode.StatusCode != nil {
		second = resp.Status.StatusCode.StatusCode.Value
	}
	require.Nil(t, resp.Assertion, "an error response carries no assertion")
	return resp.Status.StatusCode.Value, second
}

func attrs(a *samllib.Assertion) map[string][]string {
	out := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				out[at.Name] = append(out[at.Name], v.Value)
			}
		}
	}
	return out
}

// --- the tests -------------------------------------------------------------------------------

func TestSAMLIntegration(t *testing.T) {
	env := setupSAMLTestEnv(t)

	t.Run("metadata", func(t *testing.T) {
		md := env.metadata(t)
		require.Equal(t, env.realmURL+"/saml/metadata", md.EntityID)
		idp := md.IDPSSODescriptors[0]
		require.Equal(t, "urn:oasis:names:tc:SAML:2.0:protocol", idp.ProtocolSupportEnumeration)
		require.Len(t, idpCerts(t, md), 1)
		var bindings []string
		for _, s := range idp.SingleSignOnServices {
			require.Equal(t, env.realmURL+"/saml/sso", s.Location)
			bindings = append(bindings, s.Binding)
		}
		require.ElementsMatch(t, []string{samllib.HTTPRedirectBinding, samllib.HTTPPostBinding}, bindings)
		require.Equal(t, env.realmURL+"/saml/slo", idp.SingleLogoutServices[0].Location)
		require.Contains(t, idp.NameIDFormats, samllib.NameIDFormat(domain.NameIDFormatPersistent))
	})

	signedSP := env.newSP(t, spOpts{name: "wiki", signed: true, slo: true, allow: true})
	plainSP := env.newSP(t, spOpts{name: "legacy", allow: true, nameID: "email", wantResign: true}) // no certificate

	// Logins are rate limited per user (Step 4): one signed-in browser is
	// shared by the cases that only need "alice has a session".
	aliceB := env.browser(t)
	aliceB.login("alice")

	t.Run("redirect binding, signed request: login, then a valid assertion", func(t *testing.T) {
		b := env.browser(t)
		u, reqID := signedSP.redirectRequest(nil)
		action, fields := b.signIn(func() (*http.Response, string) { return b.get(u) }, "alice")

		require.Equal(t, "https://wiki.example.test/acs", action)
		require.Equal(t, "relay-123", fields["RelayState"])
		a, err := signedSP.assertion(fields["SAMLResponse"], reqID)
		require.NoError(t, err, "crewjam's SP accepts our signature, audience, recipient and dates")

		require.Equal(t, env.alice.ID, a.Subject.NameID.Value, "persistent NameID = the core Subject")
		require.Equal(t, domain.NameIDFormatPersistent, a.Subject.NameID.Format)
		require.Equal(t, env.realmURL+"/saml/metadata", a.Issuer.Value)
		require.Equal(t, "https://wiki.example.test/metadata", a.Conditions.AudienceRestrictions[0].Audience.Value)
		require.NotNil(t, a.Signature, "the assertion itself is signed")
		st := a.AuthnStatements[0]
		require.NotEmpty(t, st.SessionIndex)
		require.Equal(t, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", st.AuthnContext.AuthnContextClassRef.Value)
		require.True(t, st.SessionNotOnOrAfter.After(time.Now().Add(7*time.Hour)), "the IdP session end (8h)")
		require.Equal(t, map[string][]string{
			"uid": {"alice"}, "mail": {"alice@acme.test"}, "firstName": {"Alice"}, "groups": {"admins"},
		}, attrs(a), "only what the scope maps, renamed by attribute_mappings")

		t.Run("single sign-on: a second provider, no password asked", func(t *testing.T) {
			form, reqID := plainSP.postRequest(nil)
			resp, body := b.postForm(env.realmURL+"/saml/sso", form)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			action, fields := autoPost(t, body)
			require.Equal(t, "https://legacy.example.test/acs", action)
			require.Equal(t, "post-relay", fields["RelayState"])
			a, err := plainSP.assertion(fields["SAMLResponse"], reqID)
			require.NoError(t, err)
			require.Equal(t, "alice@acme.test", a.Subject.NameID.Value, "email NameID format")

			raw, _ := base64.StdEncoding.DecodeString(fields["SAMLResponse"])
			var r samllib.Response
			require.NoError(t, xml.Unmarshal(raw, &r))
			require.NotNil(t, r.Signature, "want_response_signed: the response is signed too")
		})

		t.Run("the same session gets the same SessionIndex", func(t *testing.T) {
			u, reqID := signedSP.redirectRequest(nil)
			resp, body := b.get(u)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_, fields := autoPost(t, body)
			a2, err := signedSP.assertion(fields["SAMLResponse"], reqID)
			require.NoError(t, err)
			require.Equal(t, st.SessionIndex, a2.AuthnStatements[0].SessionIndex)
		})
	})

	t.Run("refused requests", func(t *testing.T) {
		b := aliceB
		refused := func(t *testing.T) func(*http.Response, string) {
			return func(resp *http.Response, body string) {
				t.Helper()
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.NotContains(t, body, "SAMLResponse", "nothing is sent to an unchecked destination")
			}
		}

		t.Run("unsigned, from a provider with a certificate", func(t *testing.T) {
			unsignedCopy := *signedSP.sp
			unsignedCopy.SignatureMethod = ""
			req, err := unsignedCopy.MakeAuthenticationRequest(env.realmURL+"/saml/sso", samllib.HTTPRedirectBinding, samllib.HTTPPostBinding)
			require.NoError(t, err)
			u, err := req.Redirect("", &unsignedCopy)
			require.NoError(t, err)
			refused(t)(b.get(u.String()))
		})
		t.Run("tampered after signing", func(t *testing.T) {
			u, _ := signedSP.redirectRequest(nil)
			refused(t)(b.get(strings.Replace(u, "RelayState=relay-123", "RelayState=relay-666", 1)))
		})
		t.Run("replayed", func(t *testing.T) {
			u, _ := signedSP.redirectRequest(nil)
			resp, _ := b.get(u)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			refused(t)(b.get(u))
		})
		t.Run("another ACS URL", func(t *testing.T) {
			u, _ := signedSP.redirectRequest(func(r *samllib.AuthnRequest) { r.AssertionConsumerServiceURL = "https://evil.example/acs" })
			refused(t)(b.get(u))
		})
		t.Run("expired", func(t *testing.T) {
			u, _ := signedSP.redirectRequest(func(r *samllib.AuthnRequest) { r.IssueInstant = time.Now().Add(-10 * time.Minute) })
			refused(t)(b.get(u))
		})
		t.Run("meant for another IdP", func(t *testing.T) {
			u, _ := signedSP.redirectRequest(func(r *samllib.AuthnRequest) { r.Destination = "https://other-idp.example/sso" })
			u = strings.Replace(u, "https://other-idp.example/sso", env.realmURL+"/saml/sso", 1)
			refused(t)(b.get(u))
		})
		t.Run("tampered XML signature (POST binding)", func(t *testing.T) {
			form, _ := signedSP.postRequest(nil)
			raw, _ := base64.StdEncoding.DecodeString(form.Get("SAMLRequest"))
			raw = bytes.Replace(raw, []byte("https://wiki.example.test/acs"), []byte("https://evil.example.test/a"), 1)
			form.Set("SAMLRequest", base64.StdEncoding.EncodeToString(raw))
			refused(t)(b.postForm(env.realmURL+"/saml/sso", form))
		})
		t.Run("unknown provider", func(t *testing.T) {
			stranger := *plainSP.sp
			stranger.EntityID = "https://stranger.example.test/metadata"
			req, err := stranger.MakeAuthenticationRequest(env.realmURL+"/saml/sso", samllib.HTTPRedirectBinding, samllib.HTTPPostBinding)
			require.NoError(t, err)
			u, _ := req.Redirect("", &stranger)
			resp, body := b.get(u.String())
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Contains(t, body, "Unknown application")
		})
	})

	t.Run("errors reported to the provider", func(t *testing.T) {
		t.Run("IsPassive without a session: NoPassive", func(t *testing.T) {
			b := env.browser(t)
			yes := true
			u, _ := signedSP.redirectRequest(func(r *samllib.AuthnRequest) { r.IsPassive = &yes })
			resp, body := b.get(u)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_, fields := autoPost(t, body)
			top, second := statusOf(t, fields["SAMLResponse"])
			require.Equal(t, samllib.StatusResponder, top)
			require.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:NoPassive", second)
		})
		t.Run("another NameID format: InvalidNameIDPolicy", func(t *testing.T) {
			b := env.browser(t)
			f := string(samllib.TransientNameIDFormat)
			u, _ := signedSP.redirectRequest(func(r *samllib.AuthnRequest) { r.NameIDPolicy.Format = &f })
			_, body := b.get(u)
			_, fields := autoPost(t, body)
			_, second := statusOf(t, fields["SAMLResponse"])
			require.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy", second)
		})
		t.Run("a user without access: RequestDenied", func(t *testing.T) {
			b := env.browser(t)
			b.login("bob") // not in the employees role
			u, _ := signedSP.redirectRequest(nil)
			_, body := b.get(u)
			_, fields := autoPost(t, body)
			_, second := statusOf(t, fields["SAMLResponse"])
			require.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied", second)
		})
		t.Run("consent required (Step 13): RequestDenied, fail closed", func(t *testing.T) {
			consent := env.newSP(t, spOpts{name: "consent", allow: true, mutateApp: func(u *repository.UpdateClientAppParams) {
				yes := true
				u.RequireConsent = &yes
			}})
			b := aliceB
			u, _ := consent.redirectRequest(nil)
			_, body := b.get(u)
			_, fields := autoPost(t, body)
			_, second := statusOf(t, fields["SAMLResponse"])
			require.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied", second)
		})
		t.Run("the user cancels: AuthnFailed", func(t *testing.T) {
			b := env.browser(t)
			u, _ := signedSP.redirectRequest(nil)
			resp, body := b.get(u)
			require.Contains(t, body, `data-mode="login"`)
			_, body = b.get(resp.Request.URL.String() + "&cancel=1")
			_, fields := autoPost(t, body)
			_, second := statusOf(t, fields["SAMLResponse"])
			require.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", second)
		})
	})

	t.Run("browser binding and ForceAuthn", func(t *testing.T) {
		b := env.browser(t)
		u, _ := signedSP.redirectRequest(nil)
		resp, _ := b.get(u)
		loginURL := resp.Request.URL.String()

		other := env.browser(t) // without the binding cookie
		other.login("alice")
		resp, body := other.get(loginURL)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Contains(t, body, "another browser")

		b.login("alice")
		yes := true
		u, _ = signedSP.redirectRequest(func(r *samllib.AuthnRequest) { r.ForceAuthn = &yes })
		_, body = b.get(u)
		require.Contains(t, body, `data-mode="login"`, "ForceAuthn: the password again, despite the session")
	})

	t.Run("SAML key rotation in two steps", func(t *testing.T) {
		ctx := context.Background()
		before := idpCerts(t, env.metadata(t))
		require.Len(t, before, 1)

		_, err := env.rotation.Rotate(ctx, service.RotateInput{RealmID: env.realm.ID, TriggeredBy: "test", Purpose: domain.SigningKeyPurposeSAMLSigning})
		require.NoError(t, err)
		md := env.metadata(t)
		require.Len(t, idpCerts(t, md), 2, "the pending certificate is published before it signs")

		// A provider that still only knows the old certificate keeps working.
		b := aliceB
		u, reqID := signedSP.redirectRequest(nil)
		_, body := b.get(u)
		_, fields := autoPost(t, body)
		_, err = signedSP.assertion(fields["SAMLResponse"], reqID)
		require.NoError(t, err, "signed with the old key until activation")

		_, err = env.rotation.Activate(ctx, service.ActivateInput{RealmID: env.realm.ID, TriggeredBy: "test"})
		require.NoError(t, err)
		u, reqID = signedSP.redirectRequest(nil)
		_, body = b.get(u)
		_, fields = autoPost(t, body)
		_, err = signedSP.assertion(fields["SAMLResponse"], reqID)
		require.Error(t, err, "the old metadata does not know the new key")

		signedSP.sp.IDPMetadata = env.metadata(t) // the provider reloads our metadata
		u, reqID = signedSP.redirectRequest(nil)
		_, body = b.get(u)
		_, fields = autoPost(t, body)
		_, err = signedSP.assertion(fields["SAMLResponse"], reqID)
		require.NoError(t, err)
	})
}

// --- Single Logout ---------------------------------------------------------------------------

// logoutRequest builds a LogoutRequest from s, signed in the query string.
func (s *testSP) logoutRequest(nameID, format, sessionIndex string) (string, string) {
	s.t.Helper()
	id := "_lo" + rand.Text()
	lr := &samllib.LogoutRequest{ID: id, Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: s.env.realmURL + "/saml/slo", Issuer: &samllib.Issuer{Value: s.sp.EntityID},
		NameID: &samllib.NameID{Value: nameID, Format: format}}
	if sessionIndex != "" {
		lr.SessionIndex = &samllib.SessionIndex{Value: sessionIndex}
	}
	return s.redirect(s.env.realmURL+"/saml/slo", "SAMLRequest", lr.Element(), "sp-relay"), id
}

// logoutResponse answers a LogoutRequest of the IdP.
func (s *testSP) logoutResponse(inResponseTo, relay, status string) string {
	s.t.Helper()
	lr := &samllib.LogoutResponse{ID: "_lr" + rand.Text(), InResponseTo: inResponseTo, Version: "2.0",
		IssueInstant: time.Now().UTC(), Destination: s.env.realmURL + "/saml/slo",
		Issuer: &samllib.Issuer{Value: s.sp.EntityID}, Status: samllib.Status{StatusCode: samllib.StatusCode{Value: status}}}
	return s.redirect(s.env.realmURL+"/saml/slo", "SAMLResponse", lr.Element(), relay)
}

func (s *testSP) redirect(dest, param string, el *etree.Element, relay string) string {
	s.t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, _ := doc.WriteToBytes()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if s.key != nil {
		q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
		d := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, d[:])
		require.NoError(s.t, err)
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return dest + "?" + q
}

// idpRedirect checks a message the IdP sent with the HTTP-Redirect binding
// (query string signature) and returns its XML and RelayState.
func idpRedirect(t *testing.T, location string, certs []*x509.Certificate) ([]byte, string) {
	t.Helper()
	u, err := url.Parse(location)
	require.NoError(t, err)
	raw := u.RawQuery
	i := strings.Index(raw, "&Signature=")
	require.Greater(t, i, 0, "the IdP signs what it sends")
	signed, sigPart := raw[:i], raw[i+len("&Signature="):]
	sigB64, _ := url.QueryUnescape(sigPart)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	require.NoError(t, err)
	require.Contains(t, signed, "SigAlg="+url.QueryEscape(dsig.RSASHA256SignatureMethod))
	d := sha256.Sum256([]byte(signed))
	ok := false
	for _, c := range certs {
		if rsa.VerifyPKCS1v15(c.PublicKey.(*rsa.PublicKey), crypto.SHA256, d[:], sig) == nil {
			ok = true
		}
	}
	require.True(t, ok, "signature of the IdP's redirect")
	q := u.Query()
	msg := q.Get("SAMLRequest") + q.Get("SAMLResponse")
	deflated, err := base64.StdEncoding.DecodeString(msg)
	require.NoError(t, err)
	xmlMsg, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	require.NoError(t, err)
	return xmlMsg, q.Get("RelayState")
}

func TestSAMLSingleLogoutIntegration(t *testing.T) {
	env := setupSAMLTestEnv(t)
	wiki := env.newSP(t, spOpts{name: "wiki", signed: true, slo: true, allow: true})
	crm := env.newSP(t, spOpts{name: "crm", signed: true, slo: true, allow: true, nameID: "transient"})
	noSLO := env.newSP(t, spOpts{name: "nologout", allow: true}) // no certificate, no SLO URL
	certs := idpCerts(t, env.metadata(t))

	// alice signs in to the three providers in one browser.
	b := env.browser(t)
	u, wikiReq := wiki.redirectRequest(nil)
	_, fields := b.signIn(func() (*http.Response, string) { return b.get(u) }, "alice")
	wikiA, err := wiki.assertion(fields["SAMLResponse"], wikiReq)
	require.NoError(t, err)
	u, crmReq := crm.redirectRequest(nil)
	_, body := b.get(u)
	_, fields = autoPost(t, body)
	crmA, err := crm.assertion(fields["SAMLResponse"], crmReq)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(crmA.Subject.NameID.Value, "_"), "transient NameID")
	u, noReq := noSLO.redirectRequest(nil)
	_, body = b.get(u)
	_, fields = autoPost(t, body)
	_, err = noSLO.assertion(fields["SAMLResponse"], noReq)
	require.NoError(t, err)

	t.Run("a provider without certificate cannot log anybody out", func(t *testing.T) {
		lu, _ := noSLO.logoutRequest(env.alice.ID, domain.NameIDFormatPersistent, "")
		resp, body := b.get(lu)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Contains(t, body, "sign-out request was refused")
	})
	t.Run("an unsigned LogoutRequest is refused", func(t *testing.T) {
		key := wiki.key
		wiki.key = nil
		lu, _ := wiki.logoutRequest(wikiA.Subject.NameID.Value, domain.NameIDFormatPersistent, wikiA.AuthnStatements[0].SessionIndex)
		wiki.key = key
		resp, _ := b.get(lu)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// wiki starts the logout. The browser is sent to crm, then back to wiki.
	lu, loID := wiki.logoutRequest(wikiA.Subject.NameID.Value, domain.NameIDFormatPersistent, wikiA.AuthnStatements[0].SessionIndex)
	resp, _ := b.get(lu)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://crm.example.test/slo?"), loc)

	xmlReq, relay := idpRedirect(t, loc, certs)
	var toCRM samllib.LogoutRequest
	require.NoError(t, xml.Unmarshal(xmlReq, &toCRM))
	require.Equal(t, crmA.Subject.NameID.Value, toCRM.NameID.Value, "the NameID crm received (transient)")
	require.Equal(t, crmA.AuthnStatements[0].SessionIndex, toCRM.SessionIndex.Value)
	require.Equal(t, "https://crm.example.test/slo", toCRM.Destination)

	t.Run("the IdP session is already gone", func(t *testing.T) {
		u, _ := wiki.redirectRequest(nil)
		_, body := b.get(u)
		require.Contains(t, body, `data-mode="login"`, "a new login is needed")
		toks, err := env.tokens.ListBySession(context.Background(), sessionOf(t, env, wikiA))
		require.NoError(t, err)
		for _, tok := range toks {
			require.True(t, tok.Revoked, "%s revoked with the session", tok.Type)
		}
	})

	// crm confirms; the IdP answers wiki. "nologout" has no SLO URL: partial.
	resp, _ = b.get(crm.logoutResponse(toCRM.ID, relay, samllib.StatusSuccess))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc = resp.Header.Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://wiki.example.test/slo?"), loc)
	xmlResp, relay := idpRedirect(t, loc, certs)
	require.Equal(t, "sp-relay", relay, "the initiator's RelayState comes back")
	var final samllib.LogoutResponse
	require.NoError(t, xml.Unmarshal(xmlResp, &final))
	require.Equal(t, loID, final.InResponseTo)
	require.Equal(t, samllib.StatusSuccess, final.Status.StatusCode.Value)
	require.NotNil(t, final.Status.StatusCode.StatusCode)
	require.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:PartialLogout", final.Status.StatusCode.StatusCode.Value,
		"a participant without SLO URL could not be told")

	t.Run("a replayed LogoutRequest is refused", func(t *testing.T) {
		resp, _ := b.get(lu)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
	t.Run("a LogoutResponse for a finished logout", func(t *testing.T) {
		resp, body := b.get(crm.logoutResponse(toCRM.ID, relay, samllib.StatusSuccess))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Contains(t, body, "sign-out has expired")
	})
}

func TestSAMLSingleLogoutWithoutBrowserSession(t *testing.T) {
	env := setupSAMLTestEnv(t)
	wiki := env.newSP(t, spOpts{name: "wiki", signed: true, slo: true, allow: true})
	certs := idpCerts(t, env.metadata(t))

	b := env.browser(t)
	u, reqID := wiki.redirectRequest(nil)
	_, fields := b.signIn(func() (*http.Response, string) { return b.get(u) }, "alice")
	a, err := wiki.assertion(fields["SAMLResponse"], reqID)
	require.NoError(t, err)

	// Another browser (no IdP cookie): the SessionIndex alone finds the session.
	other := env.browser(t)
	lu, loID := wiki.logoutRequest(a.Subject.NameID.Value, domain.NameIDFormatPersistent, a.AuthnStatements[0].SessionIndex)
	resp, _ := other.get(lu)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	xmlResp, _ := idpRedirect(t, resp.Header.Get("Location"), certs)
	var final samllib.LogoutResponse
	require.NoError(t, xml.Unmarshal(xmlResp, &final))
	require.Equal(t, loID, final.InResponseTo)
	require.Nil(t, final.Status.StatusCode.StatusCode, "complete logout: nobody else to tell")

	u, _ = wiki.redirectRequest(nil)
	_, body := b.get(u)
	require.Contains(t, body, `data-mode="login"`, "the first browser's session was revoked")
}

// sessionOf finds the IdP session behind an assertion (its SessionIndex).
func sessionOf(t *testing.T, env *samlTestEnv, a *samllib.Assertion) string {
	t.Helper()
	tok, err := env.tokens.GetByJTI(context.Background(), a.AuthnStatements[0].SessionIndex)
	require.NoError(t, err)
	return tok.SessionID
}
