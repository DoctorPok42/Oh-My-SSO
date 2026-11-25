package httpserver_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The admin console sets a client's grants and its service account roles.
func TestAdmin_Integration_ServiceAccount(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"
	_, roles := e.call(t, at, http.MethodGet, realm+"/roles", nil)
	var support string
	for _, x := range roles["items"].([]any) {
		if r := x.(map[string]any); r["name"] == "support" {
			support = r["id"].(string)
		}
	}
	require.NotEmpty(t, support)

	token := func(clientID, secret string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, e.idp.URL+"/r/demo/oidc/token",
			strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, secret)
		resp, err := e.idp.Client().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	// A machine client: no redirect URI needed.
	status, out := e.call(t, at, http.MethodPost, realm+"/clients", map[string]any{"name": "Reporting", "protocol": "oidc",
		"grant_types": []string{"client_credentials"}, "service_role_ids": []string{support}})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	client := out["client"].(map[string]any)
	id, clientID, secret := client["id"].(string), client["client_id"].(string), out["secret"].(string)
	require.Equal(t, []any{"client_credentials"}, client["oidc"].(map[string]any)["grant_types"])
	require.Equal(t, support, client["service_roles"].([]any)[0].(map[string]any)["id"])
	require.Equal(t, http.StatusOK, token(clientID, secret))

	// The token shows under the "client" actor filter.
	status, out = e.call(t, at, http.MethodGet, realm+"/audit-logs?actor=client", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	issued := out["items"].([]any)[0].(map[string]any)
	require.Equal(t, "token.issued", issued["action"])
	require.Equal(t, clientID, issued["details"].(map[string]any)["client_id"])

	// A public client cannot have a service account.
	status, out = e.call(t, at, http.MethodPost, realm+"/clients", map[string]any{"name": "SPA", "protocol": "oidc", "public": true,
		"redirect_uris": []string{"https://spa.example.test/cb"}, "grant_types": []string{"authorization_code", "client_credentials"}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)

	// No grant at all is refused, on the field the drawer shows.
	status, out = e.call(t, at, http.MethodPatch, realm+"/clients/"+id, map[string]any{"grant_types": []string{}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
	require.Equal(t, "grant_types", out["field"])

	// Back to a sign-in client: the roles go, and so does the grant.
	status, out = e.call(t, at, http.MethodPatch, realm+"/clients/"+id, map[string]any{
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://reporting.example.test/cb"},
		"service_role_ids": []string{}})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Empty(t, out["service_roles"])
	require.Equal(t, []any{"authorization_code"}, out["oidc"].(map[string]any)["grant_types"])
	require.NotEqual(t, http.StatusOK, token(clientID, secret))

	status, out = e.call(t, at, http.MethodGet, realm+"/audit-logs?action=client.updated", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	changed := out["items"].([]any)[0].(map[string]any)["details"].(map[string]any)["changed"]
	require.Contains(t, changed, "grant_types")
	require.Contains(t, changed, "service_roles")
}
