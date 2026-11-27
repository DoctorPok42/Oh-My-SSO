package httpserver_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent/clientscope"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/storage/entstore"
)

// clientAssertion signs a private_key_jwt assertion (RFC 7523, section 3).
// mods change its claims (the refused cases).
func clientAssertion(t *testing.T, key *rsa.PrivateKey, kid, clientID, aud string, mods ...func(map[string]any)) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT"))
	require.NoError(t, err)
	now := time.Now()
	claims := map[string]any{"iss": clientID, "sub": clientID, "aud": aud,
		"jti": rand.Text(), "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix()}
	for _, mod := range mods {
		mod(claims)
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	out, err := jws.CompactSerialize()
	require.NoError(t, err)
	return out
}

// postForm posts to an OAuth endpoint, without HTTP Basic.
func (e *oidcTestEnv) postForm(t *testing.T, endpoint string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := e.ts.Client().PostForm(endpoint, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// audience: "aud" is a string or an array (RFC 7519, section 4.1.3).
func audience(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, s := range a {
			out = append(out, s.(string))
		}
		return out
	}
	return nil
}

func (e *oidcTestEnv) newAPIResource(t *testing.T, identifier string, scopeNames ...string) {
	t.Helper()
	ids, err := e.ent.ClientScope.Query().Where(clientscope.RealmID(e.realm.ID), clientscope.NameIn(scopeNames...)).IDs(e.ctx())
	require.NoError(t, err)
	require.Len(t, ids, len(scopeNames))
	_, err = entstore.NewApiResourceRepository(e.ent).Create(e.ctx(), repository.CreateApiResourceParams{
		RealmID: e.realm.ID, Identifier: identifier, Name: identifier, ScopeIDs: ids})
	require.NoError(t, err)
}

func TestOIDC_Integration_PrivateKeyJWT(t *testing.T) {
	// Many refused assertions on purpose: not this test's limit to check.
	limits := httpserver.DefaultProtocolLimits
	limits.ClientFailuresPerIP = httpserver.RateRule{Max: 100, Window: time.Minute}
	e := setupOIDCTestEnv(t, httpserver.WithProtocolLimits(limits))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig"}}})
	require.NoError(t, err)
	_, secret := e.newMachineClient(t, machineClientID, func(in *service.OIDCClientInput) {
		in.TokenEndpointAuthMethod, in.JWKS = "private_key_jwt", string(jwks)
	})
	require.Empty(t, secret, "no secret is shared")
	const reportsAPI = "https://reports.acme.test"
	e.newAPIResource(t, reportsAPI, "reports.read")

	token := func(t *testing.T, assertion string, extra url.Values) (int, map[string]any) {
		form := url.Values{"grant_type": {"client_credentials"}, "client_assertion": {assertion},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}}
		for k, v := range extra {
			form[k] = v
		}
		return e.postForm(t, e.disc.TokenEndpoint, form)
	}
	sign := func() string { return clientAssertion(t, key, "k1", machineClientID, e.disc.Issuer) }

	t.Run("discovery", func(t *testing.T) {
		require.Contains(t, e.disc.TokenAuthMethods, "private_key_jwt")
		require.Equal(t, []string{"RS256"}, e.disc.TokenAuthAlgs)
	})

	t.Run("a signed assertion gets a token, once", func(t *testing.T) {
		assertion := sign()
		status, out := token(t, assertion, nil)
		require.Equal(t, http.StatusOK, status, out)
		claims := e.verifyJWT(t, out["access_token"].(string))
		require.Equal(t, machineClientID, claims["sub"])
		require.Equal(t, "reports.read", claims["scope"])

		status, out = token(t, assertion, nil)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "invalid_client", out["error"], "a replayed assertion is refused")
	})

	t.Run("refused assertions", func(t *testing.T) {
		for name, assertion := range map[string]string{
			"another key":      clientAssertion(t, other, "k1", machineClientID, e.disc.Issuer),
			"another audience": clientAssertion(t, key, "k1", machineClientID, "https://elsewhere.example"),
			"unknown kid":      clientAssertion(t, key, "k2", machineClientID, e.disc.Issuer),
			"a secret client":  clientAssertion(t, key, "k1", webClientID, e.disc.Issuer),
			"not even a JWT":   "abc",
			// Without jti, nothing stops a replay (OIDC Core, section 9).
			"no jti": clientAssertion(t, key, "k1", machineClientID, e.disc.Issuer,
				func(c map[string]any) { delete(c, "jti") }),
			"expires in two hours": clientAssertion(t, key, "k1", machineClientID, e.disc.Issuer,
				func(c map[string]any) { c["exp"] = time.Now().Add(2 * time.Hour).Unix() }),
		} {
			status, out := token(t, assertion, nil)
			require.Equal(t, http.StatusUnauthorized, status, name)
			require.Equal(t, "invalid_client", out["error"], name)
		}
		// A client_id other than the assertion's issuer, at /introspect: only
		// the assertion check refuses it there (client_credentials has its own).
		status, out := e.postForm(t, e.disc.IntrospectionEndpoint, url.Values{"token": {"x"}, "client_id": {webClientID},
			"client_assertion": {sign()}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}})
		require.Equal(t, http.StatusUnauthorized, status, "client_id of another client: %v", out)
		require.Equal(t, "invalid_client", out["error"])
		status, out = token(t, sign(), url.Values{"client_assertion_type": {"urn:example:other"}})
		require.Equal(t, http.StatusBadRequest, status, "wrong client_assertion_type")
		require.Equal(t, "invalid_request", out["error"])
		status, out = token(t, sign(), url.Values{"client_secret": {"x"}})
		require.Equal(t, http.StatusBadRequest, status, "two authentication methods")
		require.Equal(t, "invalid_request", out["error"])
	})

	t.Run("code flow and refresh of a web client without secret", func(t *testing.T) {
		const keyedClient, redirect = "keyed-web", "https://keyed.example.test/cb"
		_, secret, err := service.NewOIDCClientService(entstore.NewClientRepository(e.ent), entstore.NewClientScopeRepository(e.ent),
			entstore.NewRoleRepository(e.ent), entstore.NewGroupRepository(e.ent)).Create(e.ctx(), service.OIDCClientInput{
			RealmID: e.realm.ID, ClientID: keyedClient, RedirectURIs: []string{redirect}, Scopes: []string{"offline_access"},
			AllowRoles: []string{"employees"}, TokenEndpointAuthMethod: "private_key_jwt", JWKS: string(jwks)})
		require.NoError(t, err)
		require.Empty(t, secret)
		assertion := func() url.Values {
			return url.Values{"client_assertion": {clientAssertion(t, key, "k1", keyedClient, e.disc.Issuer)},
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}}
		}

		verifier := oauth2.GenerateVerifier()
		cfg := e.oauth(keyedClient, "", redirect, "offline_access")
		code := e.loginAndGetCode(t, e.newBrowser(t), cfg, "alice", oauth2.S256ChallengeOption(verifier))
		form := assertion()
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", redirect)
		form.Set("code_verifier", verifier)
		status, out := e.postForm(t, e.disc.TokenEndpoint, form)
		require.Equal(t, http.StatusOK, status, out)
		require.Equal(t, []string{keyedClient}, audience(e.verifyJWT(t, out["id_token"].(string))["aud"]))

		form = assertion()
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", out["refresh_token"].(string))
		status, out = e.postForm(t, e.disc.TokenEndpoint, form)
		require.Equal(t, http.StatusOK, status, out)

		// Without the assertion, the client_id alone is not enough.
		status, out = e.postForm(t, e.disc.TokenEndpoint, url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {out["refresh_token"].(string)}, "client_id": {keyedClient}})
		require.Contains(t, []int{http.StatusBadRequest, http.StatusUnauthorized}, status)
		require.Equal(t, "invalid_client", out["error"], out)
	})

	t.Run("introspection with an assertion", func(t *testing.T) {
		_, out := token(t, sign(), nil)
		status, res := e.postForm(t, e.disc.IntrospectionEndpoint, url.Values{"token": {out["access_token"].(string)},
			"client_assertion": {sign()}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}})
		require.Equal(t, http.StatusOK, status, res)
		require.Equal(t, true, res["active"])
	})

	t.Run("a token for an API resource (RFC 8707)", func(t *testing.T) {
		status, out := token(t, sign(), url.Values{"resource": {reportsAPI}})
		require.Equal(t, http.StatusOK, status, out)
		claims := e.verifyJWT(t, out["access_token"].(string))
		require.Equal(t, []string{reportsAPI}, audience(claims["aud"]))
		require.Equal(t, machineClientID, claims["client_id"])

		res := e.postToken(t, e.disc.IntrospectionEndpoint, webClientID, e.webSecret, out["access_token"].(string))
		require.Equal(t, []string{reportsAPI}, audience(res["aud"]))

		status, out = token(t, sign(), url.Values{"resource": {"https://unknown.acme.test"}})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_target", out["error"])

		// reports.write is a scope of the client, but no role of its service
		// account gives it: no token for an API that only defines it.
		const writeAPI = "https://reports-admin.acme.test"
		e.newAPIResource(t, writeAPI, "reports.write")
		status, out = token(t, sign(), url.Values{"resource": {writeAPI}})
		require.Equal(t, http.StatusBadRequest, status, out)
		require.Equal(t, "invalid_target", out["error"])
	})
}

func TestOIDC_Integration_APIResources(t *testing.T) {
	e := setupOIDCTestEnv(t)
	const api = "https://api.acme.test"
	e.newAPIResource(t, api, "groups") // the web client may ask for "groups"
	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI, "email", "groups", "offline_access")
	resource := oauth2.SetAuthURLParam("resource", api)
	// flow: a login with PKCE, then the code exchange.
	flow := func(t *testing.T, authorize []oauth2.AuthCodeOption, exchange ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
		verifier := oauth2.GenerateVerifier()
		code := e.loginAndGetCode(t, e.newBrowser(t), cfg, "alice", append(authorize, oauth2.S256ChallengeOption(verifier))...)
		return cfg.Exchange(e.ctx(), code, append(exchange, oauth2.VerifierOption(verifier))...)
	}

	t.Run("the access token is for the API, the ID token for the client", func(t *testing.T) {
		tok, err := flow(t, []oauth2.AuthCodeOption{resource}, resource)
		require.NoError(t, err)

		access := e.verifyJWT(t, tok.AccessToken)
		require.Equal(t, []string{api}, audience(access["aud"]))
		require.Equal(t, webClientID, access["client_id"])
		require.Contains(t, access["scope"], "groups")
		id := e.verifyJWT(t, tok.Extra("id_token").(string))
		require.Equal(t, []string{webClientID}, audience(id["aud"]))

		status, _ := e.userinfo(t, tok.AccessToken)
		require.Equal(t, http.StatusOK, status)

		// The refresh token keeps the grant: the next access token is for the API too.
		next, err := cfg.TokenSource(e.ctx(), &oauth2.Token{RefreshToken: tok.RefreshToken, Expiry: time.Now().Add(-time.Hour)}).Token()
		require.NoError(t, err)
		require.Equal(t, []string{api}, audience(e.verifyJWT(t, next.AccessToken)["aud"]))
		require.Equal(t, []string{webClientID}, audience(e.verifyJWT(t, next.Extra("id_token").(string))["aud"]))
	})

	t.Run("without resource nothing changes", func(t *testing.T) {
		tok, err := flow(t, nil)
		require.NoError(t, err)
		require.Equal(t, []string{webClientID}, audience(e.verifyJWT(t, tok.AccessToken)["aud"]))
	})

	t.Run("an unknown resource at /authorize: invalid_target", func(t *testing.T) {
		b := e.newBrowser(t)
		resp := b.get(cfg.AuthCodeURL("st", oauth2.S256ChallengeOption(oauth2.GenerateVerifier()),
			oauth2.SetAuthURLParam("resource", "https://unknown.acme.test")))
		require.Equal(t, "invalid_target", errorFromRedirect(t, resp, webRedirectURI))
	})

	t.Run("the token request may not add a resource", func(t *testing.T) {
		_, err := flow(t, nil, resource)
		var re *oauth2.RetrieveError
		require.ErrorAs(t, err, &re)
		require.Equal(t, "invalid_target", re.ErrorCode, strings.TrimSpace(string(re.Body)))
	})
}
