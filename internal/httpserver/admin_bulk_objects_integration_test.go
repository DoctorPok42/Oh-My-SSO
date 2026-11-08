package httpserver_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// download is a GET whose answer is a file.
func (e *adminTestEnv) download(t *testing.T, token, path string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.api.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := e.api.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", raw)
	return string(raw)
}

func TestAdmin_Integration_BulkClients(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"
	post := func(path string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return e.call(t, at, http.MethodPost, realm+path, body)
	}

	status, out := post("/clients", map[string]any{"name": "Wiki", "protocol": "oidc", "redirect_uris": []string{"https://wiki.example.test/cb"}})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	wiki := out["client"].(map[string]any)["id"].(string)
	secret := out["secret"].(string)
	require.NotEmpty(t, secret)

	status, out = post("/clients/bulk", map[string]any{"action": "suspend", "ids": []string{wiki, "ghost"}})
	requireBulk(t, status, out, 1, 1, 0)
	status, client := e.call(t, at, http.MethodGet, realm+"/clients/"+wiki, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "inactive", client["status"])
	status, out = post("/clients/bulk", map[string]any{"action": "suspend", "ids": []string{wiki}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "already_suspended", bulkItem(t, out, wiki)["code"])
	status, out = post("/clients/bulk", map[string]any{"action": "reactivate", "ids": []string{wiki}})
	requireBulk(t, status, out, 1, 0, 0)

	// The configuration comes out without a secret.
	status, out = e.call(t, at, http.MethodGet, realm+"/clients/export?ids="+wiki, nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Len(t, out["items"], 1)
	raw, _ := json.Marshal(out)
	require.NotContains(t, string(raw), secret)
	status, out = e.call(t, at, http.MethodGet, realm+"/clients/export", nil)
	require.Equal(t, http.StatusBadRequest, status, "%v", out)

	status, out = post("/clients/bulk", map[string]any{"action": "delete", "ids": []string{wiki}})
	requireBulk(t, status, out, 1, 0, 0)

	// A client managed by the configuration stays as it is.
	status, list := e.call(t, at, http.MethodGet, "/api/v1/realms/master/clients", nil)
	require.Equal(t, http.StatusOK, status)
	var managed string
	for _, x := range list["items"].([]any) {
		if c := x.(map[string]any); c["managed_by"] == "config" {
			managed = c["id"].(string)
		}
	}
	require.NotEmpty(t, managed)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/master/clients/bulk", map[string]any{"action": "delete", "ids": []string{managed}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "managed_by_config", bulkItem(t, out, managed)["code"])
}

func TestAdmin_Integration_BulkAccess(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"
	post := func(path string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return e.call(t, at, http.MethodPost, realm+path, body)
	}

	// Roles: a copy keeps the rights, not the members; a role in use stays.
	_, roles := e.call(t, at, http.MethodGet, realm+"/roles", nil)
	support := roles["items"].([]any)[0].(map[string]any)["id"].(string)
	alice := e.invite(t, at, "alice")
	status, out := post("/users/bulk", map[string]any{"action": "add_role", "ids": []string{alice}, "role_id": support})
	requireBulk(t, status, out, 1, 0, 0)
	status, out = post("/roles/bulk", map[string]any{"action": "delete", "ids": []string{support}})
	requireBulk(t, status, out, 0, 1, 0)
	item := bulkItem(t, out, support)
	require.Equal(t, "in_use", item["code"])
	require.Contains(t, item["message"], "1 user")

	status, out = post("/roles/bulk", map[string]any{"action": "duplicate", "ids": []string{support}})
	requireBulk(t, status, out, 1, 0, 0)
	status, out = post("/roles/bulk", map[string]any{"action": "duplicate", "ids": []string{support}})
	requireBulk(t, status, out, 1, 0, 0)
	_, roles = e.call(t, at, http.MethodGet, realm+"/roles", nil)
	names := map[string]float64{}
	var copied string
	for _, x := range roles["items"].([]any) {
		r := x.(map[string]any)
		names[r["name"].(string)] = r["members"].(float64)
		if r["name"] == "support-copy" {
			copied = r["id"].(string)
		}
	}
	require.Equal(t, map[string]float64{"support": 1, "support-copy": 0, "support-copy-2": 0}, names)
	status, out = post("/roles/bulk", map[string]any{"action": "delete", "ids": []string{copied}})
	requireBulk(t, status, out, 1, 0, 0)

	// Groups: the pasted list, then the deletion.
	_, groups := e.call(t, at, http.MethodGet, realm+"/groups", nil)
	staff := groups["items"].([]any)[0].(map[string]any)["id"].(string)
	e.invite(t, at, "bob")
	status, out = post("/groups/"+staff+"/members/bulk", map[string]any{"identifiers": []string{"alice", "bob@example.test", "nobody", " alice "}})
	requireBulk(t, status, out, 2, 1, 0)
	require.Equal(t, "not_found", bulkItem(t, out, "nobody")["code"])
	status, out = post("/groups/"+staff+"/members/bulk", map[string]any{"identifiers": []string{"alice"}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "already_member", bulkItem(t, out, "alice")["code"])
	status, out = post("/groups/bulk", map[string]any{"action": "delete", "ids": []string{staff}})
	requireBulk(t, status, out, 1, 0, 0)
	status, detail := e.call(t, at, http.MethodGet, realm+"/users/"+alice, nil)
	require.Equal(t, http.StatusOK, status)
	require.Empty(t, detail["groups"])

	// Client scopes: the unitary guardrails apply.
	status, out = post("/client-scopes", map[string]any{"name": "extra", "protocol": "oidc"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	extra := out["id"].(string)
	status, out = post("/client-scopes/bulk", map[string]any{"action": "delete", "ids": []string{extra, "ghost"}})
	requireBulk(t, status, out, 1, 1, 0)

	// Timeouts: lifted once, not twice.
	status, out = post("/timeouts", map[string]any{"target_type": "user", "target_id": alice, "reason": "investigation"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	timeout := out["id"].(string)
	status, out = post("/timeouts/bulk", map[string]any{"action": "lift", "ids": []string{timeout}})
	requireBulk(t, status, out, 1, 0, 0)
	require.Equal(t, "alice", bulkItem(t, out, timeout)["label"])
	status, out = post("/timeouts/bulk", map[string]any{"action": "lift", "ids": []string{timeout}})
	requireBulk(t, status, out, 0, 1, 0)

	// Audit: the export of a selection holds those entries and no others.
	status, log := e.call(t, at, http.MethodGet, realm+"/audit-logs?limit=2", nil)
	require.Equal(t, http.StatusOK, status)
	first := log["items"].([]any)[0].(map[string]any)["id"].(string)
	second := log["items"].([]any)[1].(map[string]any)["id"].(string)
	body := e.download(t, at, realm+"/audit-logs/export?format=json&ids="+first)
	require.Contains(t, body, first)
	require.NotContains(t, body, second)
	require.Contains(t, body, `"count":1`)
}


func TestAdmin_Integration_BulkRoleMFA(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"
	post := func(body map[string]any) (int, map[string]any) {
		t.Helper()
		return e.call(t, at, http.MethodPost, realm+"/mfa-policies/roles/bulk", body)
	}
	line := func(id string) map[string]any {
		t.Helper()
		status, out := e.call(t, at, http.MethodGet, realm+"/mfa-policies", nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		for _, x := range out["roles"].([]any) {
			if l := x.(map[string]any); l["role"].(map[string]any)["id"] == id {
				return l
			}
		}
		t.Fatalf("role %s not in the MFA policies", id)
		return nil
	}
	_, roles := e.call(t, at, http.MethodGet, realm+"/roles", nil)
	support := roles["items"].([]any)[0].(map[string]any)["id"].(string)

	// A role on the realm default gets its own rules with MFA required.
	status, out := post(map[string]any{"action": "require", "ids": []string{support, "ghost"}})
	requireBulk(t, status, out, 1, 1, 0)
	require.Equal(t, true, line(support)["configured"])
	require.Equal(t, true, line(support)["required"])
	op := out["operation_id"].(string)
	status, audit := e.call(t, at, http.MethodGet, realm+"/audit-logs?operation="+op, nil)
	require.Equal(t, http.StatusOK, status, "%v", audit)
	require.Len(t, audit["items"], 1, "the MFA policy change carries the operation id")

	status, out = post(map[string]any{"action": "require", "ids": []string{support}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "already_required", bulkItem(t, out, support)["code"])

	// The other settings of the role are kept.
	status, out = post(map[string]any{"action": "step_up_on", "ids": []string{support}})
	requireBulk(t, status, out, 1, 0, 0)
	status, out = post(map[string]any{"action": "optional", "ids": []string{support}})
	requireBulk(t, status, out, 1, 0, 0)
	l := line(support)
	require.Equal(t, false, l["required"])
	require.Equal(t, true, l["step_up_for_sensitive_actions"])

	status, out = post(map[string]any{"action": "inherit", "ids": []string{support}})
	requireBulk(t, status, out, 1, 0, 0)
	require.Equal(t, false, line(support)["configured"])
	status, out = post(map[string]any{"action": "inherit", "ids": []string{support}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "already_default", bulkItem(t, out, support)["code"])
	// Off on a role that follows the default: nothing to write.
	status, out = post(map[string]any{"action": "optional", "ids": []string{support}})
	requireBulk(t, status, out, 0, 1, 0)

	status, out = post(map[string]any{"action": "nope", "ids": []string{support}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
}

func TestAdmin_Integration_BulkLimitSetting(t *testing.T) {
	e, at := userImportEnv(t)
	const realm = "/api/v1/realms/demo"

	status, out := e.call(t, at, http.MethodGet, realm+"/bulk-limit", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, 100, out["limit"])

	for _, bad := range []int{0, 501} {
		status, out = e.call(t, at, http.MethodPatch, realm+"/settings", map[string]any{"bulk_limit": bad})
		require.Equal(t, http.StatusBadRequest, status, "%v", out)
		require.Equal(t, "bulk_limit", out["field"])
	}
	status, out = e.call(t, at, http.MethodPatch, realm+"/settings", map[string]any{"bulk_limit": 2})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, 2, out["bulk_limit"])
	status, out = e.call(t, at, http.MethodGet, realm+"/bulk-limit", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, 2, out["limit"])

	ids := []string{e.invite(t, at, "ann"), e.invite(t, at, "bob"), e.invite(t, at, "cid")}
	status, out = e.call(t, at, http.MethodPost, realm+"/users/bulk", map[string]any{"action": "suspend", "ids": ids})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
	require.Equal(t, "bulk_limit", out["error"])
	status, out = e.call(t, at, http.MethodPost, realm+"/users/bulk", map[string]any{"action": "suspend", "ids": ids[:2]})
	requireBulk(t, status, out, 2, 0, 0)

	// The other realms keep theirs.
	status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/master/bulk-limit", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, 100, out["limit"])
}
