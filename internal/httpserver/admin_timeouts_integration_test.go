package httpserver_test

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// The timeouts of the Admin API: create, list, change, lift, the
// guardrails of the master realm, the audit trail, and the permission
// catalogue brought up to date on an instance bootstrapped before it.
func TestAdmin_Integration_Timeouts(t *testing.T) {
	e := setupAdminTestEnv(t)
	ctx := context.Background()

	res, err := e.admin.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "root@example.test",
		AdminConsoleURL: adminConsoleURL, Actor: "cli:test@host"})
	require.NoError(t, err)
	e.activate(t, res.ActivationURL)
	console := &oauth2.Config{ClientID: "sso-admin", ClientSecret: res.ClientSecret,
		RedirectURL: adminConsoleURL + "/auth/callback", Scopes: []string{"openid", "profile", "email", "offline_access"},
		Endpoint: oauth2.Endpoint{AuthURL: e.idp.URL + "/r/master/oidc/authorize", TokenURL: e.idp.URL + "/r/master/oidc/token",
			AuthStyle: oauth2.AuthStyleInHeader}}
	var secret string
	at := e.signIn(t, console, "root", &secret).AccessToken

	status, me := e.call(t, at, http.MethodGet, "/api/v1/me", nil)
	require.Equal(t, http.StatusOK, status, "%v", me)
	require.Contains(t, me["permissions"], "timeout:read")
	require.Contains(t, me["permissions"], "timeout:write", "admins get the new permission at bootstrap")

	// A realm with a user to suspend.
	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms", map[string]any{"name": "demo"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users", map[string]any{
		"email": "bob@example.test", "send_email": false})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	bobID := out["user"].(map[string]any)["id"].(string)

	base := "/api/v1/realms/demo/timeouts"

	t.Run("create, list, change, lift", func(t *testing.T) {
		status, out := e.call(t, at, http.MethodPost, base, map[string]any{
			"target_type": "user", "target_id": bobID, "reason": "suspicious activity"})
		require.Equal(t, http.StatusCreated, status, "%v", out)
		id := out["id"].(string)
		require.Equal(t, "active", out["status"])
		require.Equal(t, true, out["active"])
		require.Equal(t, "bob", out["target"].(map[string]any)["name"])
		require.Equal(t, "root", out["created_by"], "the administrator's username, not user:<id>")
		require.Nil(t, out["ends_at"], "no end")
		require.NotNil(t, out["sign_out"], "started at once: signed out at once")
		require.NotNil(t, out["enforced_at"])

		status, got := e.call(t, at, http.MethodGet, base+"/"+id, nil)
		require.Equal(t, http.StatusOK, status, "%v", got)
		require.Equal(t, "suspicious activity", got["reason"])
		status, _ = e.call(t, at, http.MethodGet, "/api/v1/realms/master/timeouts/"+id, nil)
		require.Equal(t, http.StatusNotFound, status, "another realm's timeout is not found")

		status, list := e.call(t, at, http.MethodGet, base, nil)
		require.Equal(t, http.StatusOK, status, "%v", list)
		require.EqualValues(t, 1, list["total"], "current by default")
		status, list = e.call(t, at, http.MethodGet, base+"?status=past", nil)
		require.Equal(t, http.StatusOK, status)
		require.EqualValues(t, 0, list["total"])
		status, list = e.call(t, at, http.MethodGet, base+"?status=bogus", nil)
		require.Equal(t, http.StatusBadRequest, status, "%v", list)

		end := e.clock.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
		status, out = e.call(t, at, http.MethodPatch, base+"/"+id, map[string]any{
			"reason": "fraud check", "ends_at": end.Format(time.RFC3339)})
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, "fraud check", out["reason"])
		require.Equal(t, end.Format(time.RFC3339), out["ends_at"])

		status, out = e.call(t, at, http.MethodPatch, base+"/"+id, map[string]any{"ends_at": ""})
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Nil(t, out["ends_at"], "the end was removed")

		status, out = e.call(t, at, http.MethodPost, base+"/"+id+"/lift", nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, "lifted", out["status"])
		require.Equal(t, "root", out["lifted_by"])

		status, out = e.call(t, at, http.MethodPost, base+"/"+id+"/lift", nil)
		require.Equal(t, http.StatusConflict, status, "%v", out)
		require.Equal(t, "timeout_over", out["error"])

		status, list = e.call(t, at, http.MethodGet, base+"?status=past", nil)
		require.Equal(t, http.StatusOK, status)
		require.EqualValues(t, 1, list["total"])

		status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?limit=200", nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		var actions []string
		for _, it := range out["items"].([]any) {
			actions = append(actions, it.(map[string]any)["action"].(string))
		}
		for _, a := range []string{"admin.timeout.create", "admin.timeout.update", "admin.timeout.lift", "timeout_enforced"} {
			require.True(t, slices.Contains(actions, a), "%s in %v", a, actions)
		}
	})

	t.Run("a scheduled timeout and bad input", func(t *testing.T) {
		starts := e.clock.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
		status, out := e.call(t, at, http.MethodPost, base, map[string]any{"target_type": "user", "target_id": bobID,
			"reason": "maintenance", "starts_at": starts.Format(time.RFC3339), "ends_at": starts.Add(time.Hour).Format(time.RFC3339)})
		require.Equal(t, http.StatusCreated, status, "%v", out)
		require.Equal(t, "scheduled", out["status"])
		require.Nil(t, out["sign_out"])
		require.Nil(t, out["enforced_at"])

		cases := []struct {
			body  map[string]any
			field string
		}{
			{map[string]any{"target_type": "user", "target_id": bobID}, "reason"},
			{map[string]any{"target_type": "user", "target_id": "nobody", "reason": "x"}, "target_id"},
			{map[string]any{"target_type": "realm", "target_id": bobID, "reason": "x"}, "target_type"},
			{map[string]any{"target_type": "user", "target_id": bobID, "reason": "x", "ends_at": "tomorrow"}, "ends_at"},
		}
		for _, c := range cases {
			status, out := e.call(t, at, http.MethodPost, base, c.body)
			require.Equal(t, http.StatusBadRequest, status, "%v", out)
			require.Equal(t, c.field, out["field"], "%v", out)
		}
		status, out = e.call(t, at, http.MethodPost, base, map[string]any{"target_type": "user", "target_id": bobID,
			"reason": "x", "unknown": 1})
		require.Equal(t, http.StatusBadRequest, status, "unknown fields are refused: %v", out)
	})

	t.Run("guardrails of the master realm", func(t *testing.T) {
		status, users := e.call(t, at, http.MethodGet, "/api/v1/realms/master/users?q=root", nil)
		require.Equal(t, http.StatusOK, status)
		rootID := users["items"].([]any)[0].(map[string]any)["id"].(string)
		status, groups := e.call(t, at, http.MethodGet, "/api/v1/realms/master/groups", nil)
		require.Equal(t, http.StatusOK, status)
		ids := map[string]string{}
		for _, g := range groups["items"].([]any) {
			ids[g.(map[string]any)["name"].(string)] = g.(map[string]any)["id"].(string)
		}
		status, clients := e.call(t, at, http.MethodGet, "/api/v1/realms/master/clients", nil)
		require.Equal(t, http.StatusOK, status)
		consoleRef := clients["items"].([]any)[0].(map[string]any)["id"].(string)

		for _, c := range []struct {
			typ, id, code string
		}{
			{"user", rootID, "timeout_self"},
			{"group", ids["admins"], "timeout_admin_console"},
			{"client", consoleRef, "timeout_admin_console"},
		} {
			status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/master/timeouts",
				map[string]any{"target_type": c.typ, "target_id": c.id, "reason": "test"})
			require.Equal(t, http.StatusConflict, status, "%v", out)
			require.Equal(t, c.code, out["error"])
		}
		// The auditors (root is not a member) may be suspended.
		status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/master/timeouts",
			map[string]any{"target_type": "group", "target_id": ids["auditors"], "reason": "test"})
		require.Equal(t, http.StatusCreated, status, "%v", out)

		// And idp-admin recover timeouts lifts it.
		lifted, _, err := e.admin.RecoverTimeouts(ctx, "cli:test@host")
		require.NoError(t, err)
		require.Len(t, lifted, 1)
		require.Equal(t, "auditors", lifted[0].Target.Name)
	})

	t.Run("an instance bootstrapped before timeout:write gets it", func(t *testing.T) {
		master, err := e.admin.RealmByName(ctx, "master")
		require.NoError(t, err)
		admins, err := entstore.NewGroupRepository(e.ent).GetByRealmAndName(ctx, master.ID, service.AdminGroupName)
		require.NoError(t, err)
		perms := entstore.NewPermissionRepository(e.ent)
		write, err := perms.GetByRealmAndName(ctx, master.ID, "timeout:write")
		require.NoError(t, err)

		// The state of an older version: the permission does not exist.
		adminRepo := entstore.NewAdminRepository(e.ent)
		grants, err := adminRepo.GroupGrants(ctx, admins.ID)
		require.NoError(t, err)
		older := slices.DeleteFunc(slices.Clone(grants.PermissionIDs), func(id string) bool { return id == write.ID })
		require.NoError(t, adminRepo.SetGroupPermissions(ctx, admins.ID, older))
		require.NoError(t, perms.Delete(ctx, write.ID))

		changed, err := e.admin.SyncAdminCatalogue(ctx)
		require.NoError(t, err)
		require.True(t, changed)
		write, err = perms.GetByRealmAndName(ctx, master.ID, "timeout:write")
		require.NoError(t, err, "created again")
		grants, err = adminRepo.GroupGrants(ctx, admins.ID)
		require.NoError(t, err)
		require.Contains(t, grants.PermissionIDs, write.ID)

		changed, err = e.admin.SyncAdminCatalogue(ctx)
		require.NoError(t, err)
		require.False(t, changed, "nothing to do the second time")

		auditors, err := entstore.NewGroupRepository(e.ent).GetByRealmAndName(ctx, master.ID, service.AuditorGroupName)
		require.NoError(t, err)
		grants, err = adminRepo.GroupGrants(ctx, auditors.ID)
		require.NoError(t, err)
		require.NotContains(t, grants.PermissionIDs, write.ID, "auditors only read")
	})
}
