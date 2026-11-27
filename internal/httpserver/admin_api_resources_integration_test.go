package httpserver_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent/auditlog"
)

func TestAdmin_Integration_APIResources(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		return e.call(t, at, method, realm+path, body)
	}

	status, out := call(http.MethodPost, "/client-scopes", map[string]any{"name": "orders.read", "protocol": "oidc"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	read := out["id"].(string)
	status, out = call(http.MethodPost, "/client-scopes", map[string]any{"name": "orders.write", "protocol": "oidc"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	write := out["id"].(string)
	status, out = call(http.MethodPost, "/client-scopes", map[string]any{"name": "saml_only", "protocol": "saml2"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	saml := out["id"].(string)

	status, out = call(http.MethodPost, "/api-resources", map[string]any{"identifier": "https://orders.example.test",
		"scope_ids": []string{read}})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	id := out["id"].(string)
	require.Equal(t, "https://orders.example.test", out["name"], "no name: the identifier")
	require.Len(t, out["scopes"], 1)

	for name, body := range map[string]map[string]any{
		"taken":       {"identifier": "https://orders.example.test", "scope_ids": []string{read}},
		"relative":    {"identifier": "orders", "scope_ids": []string{read}},
		"fragment":    {"identifier": "https://x.example.test/#a", "scope_ids": []string{read}},
		"no scope":    {"identifier": "https://y.example.test"},
		"SAML scope":  {"identifier": "https://z.example.test", "scope_ids": []string{saml}},
		"other realm": {"identifier": "https://w.example.test", "scope_ids": []string{"ghost"}},
	} {
		status, out := call(http.MethodPost, "/api-resources", body)
		require.Contains(t, []int{http.StatusBadRequest, http.StatusConflict}, status, "%s: %v", name, out)
	}

	status, out = call(http.MethodPatch, "/api-resources/"+id, map[string]any{"name": "Orders", "scope_ids": []string{read, write}})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Equal(t, "Orders", out["name"])
	require.Len(t, out["scopes"], 2, "the list is replaced")
	status, out = call(http.MethodPatch, "/api-resources/"+id, map[string]any{"identifier": "https://new.example.test"})
	require.Equal(t, http.StatusBadRequest, status, "the identifier never changes: %v", out)

	status, out = call(http.MethodGet, "/api-resources", nil)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, out["items"], 1)

	// A scope of an API cannot be deleted: the API would silently lose it.
	status, out = call(http.MethodDelete, "/client-scopes/"+read, nil)
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "in_use", out["error"])
	status, out = call(http.MethodPost, "/client-scopes/bulk", map[string]any{"action": "delete", "ids": []string{write}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "in_use", bulkItem(t, out, write)["code"])

	status, _ = call(http.MethodDelete, "/api-resources/"+id, nil)
	require.Equal(t, http.StatusNoContent, status)
	status, _ = call(http.MethodGet, "/api-resources/"+id, nil)
	require.Equal(t, http.StatusNotFound, status)

	for _, action := range []string{"api_resource.created", "api_resource.updated", "api_resource.deleted"} {
		n, err := e.ent.AuditLog.Query().Where(auditlog.Action(action), auditlog.ResourceID(id)).Count(t.Context())
		require.NoError(t, err)
		require.Positive(t, n, action)
	}
}

func TestAdmin_Integration_PrivateKeyJWTClient(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1"}}})
	require.NoError(t, err)

	status, out := e.call(t, at, http.MethodPost, realm+"/clients", map[string]any{"name": "Batch", "protocol": "oidc",
		"grant_types": []string{"client_credentials"}, "token_endpoint_auth_method": "private_key_jwt", "jwks": string(jwks)})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	require.NotContains(t, out, "secret", "no secret is shared")
	client := out["client"].(map[string]any)
	id := client["id"].(string)
	oidc := client["oidc"].(map[string]any)
	require.Equal(t, "private_key_jwt", oidc["token_endpoint_auth_method"])
	require.Contains(t, oidc["jwks"], `"kid":"k1"`)
	require.Equal(t, false, oidc["has_secret"])

	status, out = e.call(t, at, http.MethodPost, realm+"/clients/"+id+"/secret", nil)
	require.Equal(t, http.StatusBadRequest, status, "no secret to rotate: %v", out)

	status, out = e.call(t, at, http.MethodPost, realm+"/clients", map[string]any{"name": "Bad", "protocol": "oidc",
		"grant_types": []string{"client_credentials"}, "token_endpoint_auth_method": "private_key_jwt"})
	require.Equal(t, http.StatusBadRequest, status, "keys required: %v", out)

	// The keys are a JWKS or a jwks_uri: one sent alone replaces the other.
	status, out = e.call(t, at, http.MethodPatch, realm+"/clients/"+id, map[string]any{"jwks_uri": "https://batch.example.test/jwks"})
	require.Equal(t, http.StatusOK, status, "%v", out)
	oidc = out["oidc"].(map[string]any)
	require.Equal(t, "https://batch.example.test/jwks", oidc["jwks_uri"])
	require.Empty(t, oidc["jwks"])
	status, out = e.call(t, at, http.MethodPatch, realm+"/clients/"+id, map[string]any{"jwks": string(jwks)})
	require.Equal(t, http.StatusOK, status, "%v", out)
	oidc = out["oidc"].(map[string]any)
	require.Empty(t, oidc["jwks_uri"])
	require.Contains(t, oidc["jwks"], `"kid":"k1"`)

	status, out = e.call(t, at, http.MethodPatch, realm+"/clients/"+id, map[string]any{
		"token_endpoint_auth_method": "client_secret_basic", "jwks": "", "jwks_uri": ""})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Empty(t, out["oidc"].(map[string]any)["jwks"], "another method drops the keys")
}
