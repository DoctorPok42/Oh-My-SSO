package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func testClient(mod func(*domain.ClientApp), scopes ...*domain.ClientScope) *core.ProtocolClient {
	app := &domain.ClientApp{
		ID: "ref-1", ClientID: "webapp", Name: "Web App", Protocol: domain.ClientAppProtocolOIDC,
		Status: domain.ClientAppActive, ClientType: domain.ClientAppTypeConfidential, RequirePKCE: true,
		RedirectURIs: []string{"https://app.example/cb"},
	}
	if mod != nil {
		mod(app)
	}
	return &core.ProtocolClient{App: app, Scopes: scopes}
}

// --- claims ---------------------------------------------------------------------

func TestBuildClaims(t *testing.T) {
	groups := &domain.ClientScope{Name: "groups", ClaimMappers: []map[string]interface{}{
		{"source_attribute": "groups", "claim_name": "groups", "token_location": []interface{}{"id_token", "access_token"}},
		{"source_attribute": "profile.department", "claim_name": "department"}, // default: id_token + userinfo
		{"source_attribute": "email", "claim_name": "sub"},                     // reserved: ignored
		{"source_attribute": "username", "claim_name": "aud"},                  // reserved: ignored
		{"source_attribute": "missing", "claim_name": "nothing"},               // no such attribute: no claim
		{"claim_name": "broken"}, // incomplete: ignored
	}}
	samlOnly := &domain.ClientScope{Name: "saml", Protocol: domain.ClientScopeProtocolSAML2, ClaimMappers: []map[string]interface{}{
		{"source_attribute": "email", "claim_name": "saml_email"},
	}}
	as := &core.IdentityAssertion{
		Subject: "sub-1",
		UserAttributes: map[string]any{
			"username": "alice", "email": "alice@acme.test", "updated_at": int64(1700000000),
			"profile.given_name": "Alice", "profile.email_verified": true, "profile.department": "R&D",
			"profile.secret_note": "never leaves", "groups": []string{"admins"}, "roles": []string{"employees"},
		},
		Scopes: []*domain.ClientScope{groups, samlOnly},
	}

	idt := buildClaims(as, nil, []string{"openid", "profile", "email", "groups"}, locIDToken, quiet)
	require.Equal(t, map[string]any{
		"preferred_username": "alice",
		"given_name":         "Alice",
		"updated_at":         int64(1700000000),
		"email":              "alice@acme.test",
		"email_verified":     true,
		"groups":             []string{"admins"},
		"department":         "R&D",
	}, idt, "minimal disclosure: profile.secret_note, roles and the SAML scope never appear")

	at := buildClaims(as, nil, []string{"openid", "profile", "email", "groups"}, locAccessToken, quiet)
	require.Equal(t, map[string]any{"groups": []string{"admins"}}, at, "standard claims stay out of access tokens")

	ui := buildClaims(as, nil, []string{"openid"}, locUserinfo, quiet)
	require.Equal(t, map[string]any{"department": "R&D"}, ui, "no profile/email scope: no standard claims")

	t.Run("email_verified only when known", func(t *testing.T) {
		as2 := &core.IdentityAssertion{UserAttributes: map[string]any{"email": "bob@acme.test"}}
		got := buildClaims(as2, nil, []string{"email"}, locIDToken, quiet)
		require.Equal(t, map[string]any{"email": "bob@acme.test"}, got)
	})

	t.Run("token_location as a single string", func(t *testing.T) {
		m, ok := parseClaimMapper(map[string]interface{}{"source_attribute": "a", "claim_name": "b", "token_location": "userinfo"})
		require.True(t, ok)
		require.Equal(t, []location{locUserinfo}, m.locations)
	})
}

func TestApplyRenames(t *testing.T) {
	pc := testClient(func(c *domain.ClientApp) {
		c.AttributeMappings = map[string]interface{}{
			"email":              "mail",     // ok
			"given_name":         "sub",      // reserved target: ignored
			"sid":                "session",  // reserved source: ignored
			"preferred_username": "groups",   // would overwrite: ignored
			"department":         "",         // empty: ignored
			"absent":             "whatever", // nothing to rename
			"family_name":        42,         // not a string: ignored
		}
	})
	claims := map[string]any{
		"email": "a@acme.test", "given_name": "Alice", "preferred_username": "alice",
		"groups": []string{"admins"}, "department": "R&D", "family_name": "Martin",
	}
	applyRenames(claims, pc.App.AttributeMappings, pc.App.ClientID, quiet)
	require.Equal(t, map[string]any{
		"mail": "a@acme.test", "given_name": "Alice", "preferred_username": "alice",
		"groups": []string{"admins"}, "department": "R&D", "family_name": "Martin",
	}, claims)
}

// --- authorize policy -------------------------------------------------------------

func TestCheckAuthorizePolicy(t *testing.T) {
	ok := func() *oidc.AuthRequest {
		return &oidc.AuthRequest{Scopes: []string{"openid"}, CodeChallenge: "x", CodeChallengeMethod: oidc.CodeChallengeMethodS256}
	}
	conf := testClient(nil)
	public := testClient(func(c *domain.ClientApp) { c.ClientType = domain.ClientAppTypePublic; c.RequirePKCE = false })
	noPKCE := testClient(func(c *domain.ClientApp) { c.RequirePKCE = false })
	consent := testClient(func(c *domain.ClientApp) { c.RequireConsent = true })

	require.NoError(t, checkAuthorizePolicy(conf, ok()))

	cases := []struct {
		name string
		pc   *core.ProtocolClient
		mod  func(*oidc.AuthRequest)
		want string
	}{
		{"no openid", conf, func(r *oidc.AuthRequest) { r.Scopes = []string{"profile"} }, "invalid_scope"},
		{"no PKCE, confidential", conf, func(r *oidc.AuthRequest) { r.CodeChallenge = "" }, "invalid_request"},
		{"no PKCE, public (require_pkce off is ignored)", public, func(r *oidc.AuthRequest) { r.CodeChallenge = "" }, "invalid_request"},
		{"plain", conf, func(r *oidc.AuthRequest) { r.CodeChallengeMethod = oidc.CodeChallengeMethodPlain }, "invalid_request"},
		{"method missing (= plain)", conf, func(r *oidc.AuthRequest) { r.CodeChallengeMethod = "" }, "invalid_request"},
		{"fragment response mode", conf, func(r *oidc.AuthRequest) { r.ResponseMode = oidc.ResponseModeFragment }, "invalid_request"},
		{"prompt=consent", conf, func(r *oidc.AuthRequest) { r.Prompt = []string{"consent"} }, "consent_required"},
		{"client requires consent (Step 13)", consent, nil, "consent_required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ok()
			if c.mod != nil {
				c.mod(r)
			}
			err := checkAuthorizePolicy(c.pc, r)
			var oe *oidc.Error
			require.ErrorAs(t, err, &oe)
			require.EqualValues(t, c.want, oe.ErrorType)
		})
	}

	r := ok()
	r.CodeChallenge, r.CodeChallengeMethod = "", ""
	require.NoError(t, checkAuthorizePolicy(noPKCE, r), "confidential with require_pkce off: PKCE optional")
}

func TestScopes(t *testing.T) {
	groups := &domain.ClientScope{Name: "groups"}
	saml := &domain.ClientScope{Name: "saml-attrs", Protocol: domain.ClientScopeProtocolSAML2}
	all := testClient(nil, groups, saml)
	require.Equal(t, []string{"openid", "profile", "email", "offline_access", "groups"},
		grantedScopes(all, []string{"openid", "profile", "email", "offline_access", "groups", "saml-attrs", "admin", "phone", "openid"}),
		"no allowed_scopes: every standard scope; custom ones need a mapping; SAML scopes never")

	restricted := testClient(func(c *domain.ClientApp) { c.AllowedScopes = []string{"openid", "email"} })
	require.Equal(t, []string{"openid", "email"}, grantedScopes(restricted, []string{"openid", "profile", "email", "offline_access"}))

	noRefresh := testClient(func(c *domain.ClientApp) { c.AllowedGrantTypes = []string{"authorization_code"} })
	require.Equal(t, []string{"openid"}, grantedScopes(noRefresh, []string{"openid", "offline_access"}),
		"offline_access needs the refresh_token grant")
}

func TestClientAdapter(t *testing.T) {
	c := &client{pc: testClient(nil), loginURL: "https://sso/r/acme/oidc/login?id="}
	require.Equal(t, op.ApplicationTypeWeb, c.ApplicationType())
	require.Equal(t, oidc.AuthMethodBasic, c.AuthMethod())
	require.Equal(t, []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}, c.GrantTypes())
	require.Equal(t, []oidc.ResponseType{oidc.ResponseTypeCode}, c.ResponseTypes())
	require.Equal(t, op.AccessTokenTypeJWT, c.AccessTokenType())
	require.Equal(t, "https://sso/r/acme/oidc/login?id=a%2Bb", c.LoginURL("a+b"))
	require.False(t, c.DevMode())

	post := &client{pc: testClient(func(a *domain.ClientApp) { a.TokenEndpointAuthMethod = "client_secret_post" })}
	require.Equal(t, oidc.AuthMethodPost, post.AuthMethod())

	spa := &client{pc: testClient(func(a *domain.ClientApp) { a.ClientType = domain.ClientAppTypePublic })}
	require.Equal(t, oidc.AuthMethodNone, spa.AuthMethod())
	require.Equal(t, op.ApplicationTypeUserAgent, spa.ApplicationType())

	native := &client{pc: testClient(func(a *domain.ClientApp) {
		a.ClientType = domain.ClientAppTypePublic
		a.RedirectURIs = []string{"http://127.0.0.1/cb"}
	})}
	require.Equal(t, op.ApplicationTypeNative, native.ApplicationType(), "loopback redirect: RFC 8252 rules")
}

func TestCheckPublicURL(t *testing.T) {
	got, err := checkPublicURL("https://sso.example.com/", false)
	require.NoError(t, err)
	require.Equal(t, "https://sso.example.com", got)

	_, err = checkPublicURL("http://localhost:8080", false)
	require.Error(t, err, "http needs AllowInsecureHTTP")
	got, err = checkPublicURL("http://localhost:8080", true)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8080", got)

	for _, bad := range []string{"", "sso.example.com", "https://sso.example.com/?a=b", "https://u:p@sso.example.com", "ftp://sso"} {
		_, err := checkPublicURL(bad, true)
		require.Error(t, err, bad)
	}
}

// --- signing through the KMS ------------------------------------------------------

// fakeSigner behaves like core.Signer on top of the KMS: SHA-256, then
// PKCS#1 v1.5 (RSA) or ASN.1 DER ECDSA.
type fakeSigner struct {
	kid string
	kt  domain.SigningKeyType
	key crypto.Signer
}

func (s *fakeSigner) KeyID() string                  { return s.kid }
func (s *fakeSigner) KeyType() domain.SigningKeyType { return s.kt }
func (s *fakeSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	return s.key.Sign(rand.Reader, h[:], crypto.SHA256)
}

func TestKMSSignerProducesValidJWS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		kt   domain.SigningKeyType
		key  crypto.Signer
	}{
		{"RS256", domain.SigningKeyRSA, rsaKey},
		{"ES256", domain.SigningKeyEC, ecKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alg, err := algFor(tc.kt)
			require.NoError(t, err)
			ks := &kmsSigner{ctx: context.Background(), signer: &fakeSigner{kid: "kid-" + tc.name, kt: tc.kt, key: tc.key},
				pub: tc.key.Public(), alg: alg}
			// The exact signer construction the library uses for id_tokens.
			signer, err := op.SignerFromKey(&signingKey{kid: "kid-" + tc.name, alg: alg, key: ks})
			require.NoError(t, err)
			obj, err := signer.Sign([]byte(`{"sub":"alice"}`))
			require.NoError(t, err)
			compact, err := obj.CompactSerialize()
			require.NoError(t, err)

			parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{alg})
			require.NoError(t, err)
			require.Equal(t, "kid-"+tc.name, parsed.Signatures[0].Header.KeyID, "the kid is in the signed header")
			payload, err := parsed.Verify(tc.key.Public())
			require.NoError(t, err)
			require.JSONEq(t, `{"sub":"alice"}`, string(payload))

			_, err = ks.SignPayload([]byte("x"), jose.PS256)
			require.Error(t, err, "a key never signs with another algorithm")
		})
	}
}

func TestDerToRawECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for range 50 { // small r or s values exercise the left padding
		h := sha256.Sum256([]byte(rand.Text()))
		der, err := ecdsa.SignASN1(rand.Reader, key, h[:])
		require.NoError(t, err)
		raw, err := derToRawECDSA(der, 32)
		require.NoError(t, err)
		require.Len(t, raw, 64)
		r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
		require.True(t, ecdsa.Verify(&key.PublicKey, h[:], r, s))
	}
	_, err = derToRawECDSA([]byte("garbage"), 32)
	require.Error(t, err)
}

func TestParsePublicKeyPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pub, err := parsePublicKeyPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	require.NoError(t, err)
	require.True(t, key.PublicKey.Equal(pub))
	_, err = parsePublicKeyPEM("not pem")
	require.Error(t, err)
}

// --- pages -------------------------------------------------------------------------

func TestReauthRequired(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	a := &Adapter{now: func() time.Time { return now }}
	started := now.Add(-time.Minute)
	oldSession := &domain.Session{CreatedAt: now.Add(-2 * time.Hour)}
	freshSession := &domain.Session{CreatedAt: now.Add(-10 * time.Second)} // created after the request started
	maxAge := func(v uint) *uint { return &v }

	for _, tc := range []struct {
		name string
		ar   authRequest
		sess *domain.Session
		want bool
	}{
		{"no constraint", authRequest{CreatedAt: started}, oldSession, false},
		{"prompt=login, old session", authRequest{CreatedAt: started, Prompt: []string{"login"}}, oldSession, true},
		{"prompt=login, login done for this request", authRequest{CreatedAt: started, Prompt: []string{"login"}}, freshSession, false},
		{"max_age=0 (library value for prompt=login), fresh", authRequest{CreatedAt: started, MaxAge: maxAge(0)}, freshSession, false},
		{"max_age=0, old session", authRequest{CreatedAt: started, MaxAge: maxAge(0)}, oldSession, true},
		{"max_age=3h, 2h-old session", authRequest{CreatedAt: started, MaxAge: maxAge(3 * 3600)}, oldSession, false},
		{"max_age=1h, 2h-old session", authRequest{CreatedAt: started, MaxAge: maxAge(3600)}, oldSession, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, a.reauthRequired(&tc.ar, tc.sess))
		})
	}
}
