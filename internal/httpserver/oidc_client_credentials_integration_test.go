package httpserver_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/ent/role"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/storage/entstore"
)

const machineClientID = "reporting"

// newMachineClient (once per env) creates a client_credentials-only client whose service
// account holds the "reporter" role, which gives the "reports.read" scope.
// "reports.write" is a scope of the client that no role gives.
func (e *oidcTestEnv) newMachineClient(t *testing.T, clientID string) (*domain.ClientApp, string) {
	t.Helper()
	ctx := e.ctx()
	scopes := entstore.NewClientScopeRepository(e.ent)
	roles := entstore.NewRoleRepository(e.ent)
	read, err := scopes.Create(ctx, repository.CreateClientScopeParams{RealmID: e.realm.ID, Name: "reports.read"})
	require.NoError(t, err)
	_, err = scopes.Create(ctx, repository.CreateClientScopeParams{RealmID: e.realm.ID, Name: "reports.write"})
	require.NoError(t, err)
	reporter, err := roles.Create(ctx, repository.CreateRoleParams{RealmID: e.realm.ID, Name: "reporter"})
	require.NoError(t, err)
	require.NoError(t, e.ent.Role.UpdateOneID(reporter.ID).AddClientScopeIDs(read.ID).Exec(ctx))
	app, secret, err := service.NewOIDCClientService(entstore.NewClientRepository(e.ent), scopes, roles,
		entstore.NewGroupRepository(e.ent)).Create(ctx, service.OIDCClientInput{
		RealmID: e.realm.ID, ClientID: clientID, GrantTypes: []string{"client_credentials"},
		Scopes: []string{"reports.read", "reports.write"}, ServiceRoles: []string{"reporter"},
	})
	require.NoError(t, err)
	return app, secret
}

// clientCredentials asks /token for a client_credentials token.
func (e *oidcTestEnv) clientCredentials(t *testing.T, clientID, secret, scope string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, _ := http.NewRequest(http.MethodPost, e.disc.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := e.ts.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// postToken: a token to /introspect or /revoke, as the given client.
func (e *oidcTestEnv) postToken(t *testing.T, endpoint, clientID, secret, token string) map[string]any {
	t.Helper()
	form := url.Values{"token": {token}}
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := e.ts.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestOIDC_Integration_ClientCredentials(t *testing.T) {
	e := setupOIDCTestEnv(t)
	app, secret := e.newMachineClient(t, machineClientID)
	introspect := func(t *testing.T, token string) map[string]any {
		return e.postToken(t, e.disc.IntrospectionEndpoint, webClientID, e.webSecret, token)
	}

	t.Run("discovery advertises the grant", func(t *testing.T) {
		require.Contains(t, e.disc.GrantTypes, "client_credentials")
	})

	t.Run("a token for the service account, without user nor session", func(t *testing.T) {
		resp, out := e.clientCredentials(t, machineClientID, secret, "")
		require.Equal(t, http.StatusOK, resp.StatusCode, out)
		require.Equal(t, "Bearer", out["token_type"])
		require.Equal(t, "reports.read", out["scope"], "the scopes of its roles, not reports.write")
		require.NotContains(t, out, "refresh_token", "RFC 6749, section 4.4.3")
		require.NotContains(t, out, "id_token")

		access := out["access_token"].(string)
		claims := e.verifyJWT(t, access)
		require.Equal(t, machineClientID, claims["sub"])
		require.Equal(t, machineClientID, claims["client_id"])
		require.Equal(t, "reports.read", claims["scope"])
		require.NotContains(t, claims, "sid")

		res := introspect(t, access)
		require.Equal(t, true, res["active"])
		require.Equal(t, machineClientID, res["sub"])
		require.Equal(t, machineClientID, res["client_id"])
		require.Equal(t, "reports.read", res["scope"])

		status, _ := e.userinfo(t, access)
		require.NotEqual(t, http.StatusOK, status, "no user behind the token: no /userinfo")

		entry, err := e.ent.AuditLog.Query().Where(auditlog.Action("token.issued"), auditlog.ResourceID(claims["jti"].(string))).Only(e.ctx())
		require.NoError(t, err)
		require.Equal(t, "client", string(entry.ActorType))
		require.Equal(t, e.realm.ID, entry.RealmID)
		require.Equal(t, machineClientID, entry.Details["client_id"])
	})

	t.Run("a scope its roles do not give is refused", func(t *testing.T) {
		for _, scope := range []string{"reports.write", "openid", "reports.read offline_access"} {
			resp, out := e.clientCredentials(t, machineClientID, secret, scope)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, scope)
			require.Equal(t, "invalid_scope", out["error"], scope)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		resp, out := e.clientCredentials(t, machineClientID, "not-the-secret", "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Equal(t, "invalid_client", out["error"])
	})

	t.Run("a client without the grant is refused", func(t *testing.T) {
		resp, out := e.clientCredentials(t, webClientID, e.webSecret, "")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "unauthorized_client", out["error"])
	})

	t.Run("a disabled role gives no scope", func(t *testing.T) {
		reporter, err := e.ent.Role.Query().Where(role.RealmID(e.realm.ID), role.Name("reporter")).OnlyID(e.ctx())
		require.NoError(t, err)
		setStatus := func(st entschema.RoleStatus) {
			require.NoError(t, e.ent.Role.UpdateOneID(reporter).SetStatus(st).Exec(e.ctx()))
		}
		setStatus(entschema.RoleInactive)
		t.Cleanup(func() { setStatus(entschema.RoleActive) })

		resp, out := e.clientCredentials(t, machineClientID, secret, "reports.read")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_scope", out["error"])
		resp, out = e.clientCredentials(t, machineClientID, secret, "")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Empty(t, out["scope"])
	})

	t.Run("a suspended application: its tokens revoked, no new one", func(t *testing.T) {
		_, out := e.clientCredentials(t, machineClientID, secret, "")
		access := out["access_token"].(string)
		cli := service.TimeoutActor{By: "cli:test"}
		c, err := e.timeouts.Create(e.ctx(), service.CreateTimeoutInput{Realm: e.realm, TargetType: domain.TimeoutTargetClientApp,
			TargetID: app.ID, Reason: "integration test", Actor: cli})
		require.NoError(t, err)

		require.Equal(t, false, introspect(t, access)["active"])
		resp, out := e.clientCredentials(t, machineClientID, secret, "")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_grant", out["error"])

		_, err = e.timeouts.Lift(e.ctx(), e.realm, c.Timeout.ID, cli)
		require.NoError(t, err)
		resp, out = e.clientCredentials(t, machineClientID, secret, "")
		require.Equal(t, http.StatusOK, resp.StatusCode, out)
	})

	t.Run("revoked, then disabled client: no longer active", func(t *testing.T) {
		_, out := e.clientCredentials(t, machineClientID, secret, "reports.read")
		revoked := out["access_token"].(string)
		e.postToken(t, e.disc.RevocationEndpoint, machineClientID, secret, revoked)
		require.Equal(t, false, introspect(t, revoked)["active"])

		_, out = e.clientCredentials(t, machineClientID, secret, "")
		access := out["access_token"].(string)
		require.Equal(t, true, introspect(t, access)["active"])
		inactive := domain.ClientAppInactive
		_, err := entstore.NewClientRepository(e.ent).Update(e.ctx(), app.ID, repository.UpdateClientAppParams{Status: &inactive})
		require.NoError(t, err)
		require.Equal(t, false, introspect(t, access)["active"])
	})
}

func TestOIDC_Integration_ClientCredentialsRateLimit(t *testing.T) {
	limits := httpserver.DefaultProtocolLimits
	limits.ClientCredentialsPerClient = httpserver.RateRule{Max: 3, Window: time.Minute}
	e := setupOIDCTestEnv(t, httpserver.WithProtocolLimits(limits))
	_, secret := e.newMachineClient(t, machineClientID)

	// Failed attempts give their hit back: someone who only knows the
	// client_id cannot use up the service's budget.
	for range 2 {
		resp, _ := e.clientCredentials(t, machineClientID, "not-the-secret", "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
	for i := range 3 {
		resp, out := e.clientCredentials(t, machineClientID, secret, "")
		require.Equal(t, http.StatusOK, resp.StatusCode, "token %d: %v", i+1, out)
	}
	resp, out := e.clientCredentials(t, machineClientID, secret, "")
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	require.Equal(t, "rate_limited", out["error"])
	require.NotEmpty(t, resp.Header.Get("Retry-After"))
}
