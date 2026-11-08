package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

const bulkUsers = "/api/v1/realms/demo/users/bulk"

// invite creates an account of realm "demo" that has no password yet.
func (e *adminTestEnv) invite(t *testing.T, at, name string) string {
	t.Helper()
	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users",
		map[string]any{"email": name + "@example.test", "username": name, "send_email": false})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	return out["user"].(map[string]any)["id"].(string)
}

// activated creates an account of realm "demo" with the password adminPassword.
func (e *adminTestEnv) activated(t *testing.T, at, name string) string {
	t.Helper()
	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users",
		map[string]any{"email": name + "@example.test", "username": name, "send_email": false})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	e.activate(t, out["activation_url"].(string))
	return out["user"].(map[string]any)["id"].(string)
}

func (e *adminTestEnv) postIdP(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := e.idp.Client().Post(e.idp.URL+path, "application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *adminTestEnv) session(t *testing.T, userID, ip string) *domain.Session {
	t.Helper()
	realm, err := e.admin.RealmByName(context.Background(), "demo")
	require.NoError(t, err)
	_, se, err := e.sessions.Create(context.Background(), service.CreateSessionInput{RealmID: realm.ID, UserID: userID, IPAddress: ip,
		AuthMethod: domain.AuthMethodPassword})
	require.NoError(t, err)
	return se
}

// bulkItem finds the outcome of one id.
func bulkItem(t *testing.T, out map[string]any, id string) map[string]any {
	t.Helper()
	for _, x := range out["items"].([]any) {
		if item := x.(map[string]any); item["id"] == id {
			return item
		}
	}
	require.Failf(t, "no item", "%s in %v", id, out)
	return nil
}

func requireBulk(t *testing.T, status int, out map[string]any, done, skipped, failed int) {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, done, out["done"], "%v", out)
	require.EqualValues(t, skipped, out["skipped"], "%v", out)
	require.EqualValues(t, failed, out["failed"], "%v", out)
}

func TestAdmin_Integration_BulkUsers(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	alice, bob := e.invite(t, at, "alice"), e.invite(t, at, "bob")

	// The whole request is refused when it cannot work.
	tooMany := make([]string, service.DefaultBulkLimit+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("id-%d", i)
	}
	status, out := e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": tooMany})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "bulk_limit", out["error"])
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "explode", "ids": []string{alice}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "reset_mfa", "ids": []string{alice}})
	require.Equal(t, http.StatusBadRequest, status, "a reason is required: %v", out)
	require.Equal(t, "reason", out["field"])
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "add_group", "ids": []string{alice}, "group_id": "nope"})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)

	// Partial result: an id repeated counts once, an unknown one is skipped.
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{alice, alice, bob, "ghost"}})
	requireBulk(t, status, out, 2, 1, 0)
	require.Equal(t, "not_found", bulkItem(t, out, "ghost")["code"])
	require.Equal(t, "alice", bulkItem(t, out, alice)["label"])
	op := out["operation_id"].(string)
	require.Regexp(t, `^op_[0-9a-f]{16}$`, op)

	// One audit entry per changed item, under the same operation.
	status, entries := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?operation="+op, nil)
	require.Equal(t, http.StatusOK, status, "%v", entries)
	require.EqualValues(t, 2, entries["total"])
	for _, x := range entries["items"].([]any) {
		require.Equal(t, audit.UserUpdated, x.(map[string]any)["action"])
	}

	// Nothing to do: skipped, and no audit entry.
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{alice}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "already_suspended", bulkItem(t, out, alice)["code"])
	status, entries = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?operation="+out["operation_id"].(string), nil)
	require.Equal(t, http.StatusOK, status, "%v", entries)
	require.EqualValues(t, 0, entries["total"])

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "reactivate", "ids": []string{alice, bob}})
	requireBulk(t, status, out, 2, 0, 0)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "reactivate", "ids": []string{alice}})
	requireBulk(t, status, out, 0, 1, 0)

	// Groups and roles: added to what the user has, not replacing it.
	_, groups := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/groups", nil)
	staff := groups["items"].([]any)[0].(map[string]any)["id"].(string)
	_, roles := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/roles", nil)
	support := roles["items"].([]any)[0].(map[string]any)["id"].(string)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/groups", map[string]any{"name": "ops"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	ops := out["id"].(string)

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "add_group", "ids": []string{alice}, "group_id": staff})
	requireBulk(t, status, out, 1, 0, 0)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "add_group", "ids": []string{alice, bob}, "group_id": ops})
	requireBulk(t, status, out, 2, 0, 0)
	status, detail := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/users/"+alice, nil)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, detail["groups"], 2, "added, not replaced")
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "add_group", "ids": []string{alice}, "group_id": ops})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "already_member", bulkItem(t, out, alice)["code"])
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "remove_group", "ids": []string{alice, bob}, "group_id": staff})
	requireBulk(t, status, out, 1, 1, 0)
	require.Equal(t, "not_member", bulkItem(t, out, bob)["code"])

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "add_role", "ids": []string{alice}, "role_id": support})
	requireBulk(t, status, out, 1, 0, 0)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "add_role", "ids": []string{alice}, "role_id": support})
	requireBulk(t, status, out, 0, 1, 0)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "remove_role", "ids": []string{alice, bob}, "role_id": support})
	requireBulk(t, status, out, 1, 1, 0)
	require.Equal(t, "not_assigned", bulkItem(t, out, bob)["code"])

	// No second factor: nothing to reset.
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "reset_mfa", "ids": []string{alice}, "reason": "phone lost"})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "no_mfa", bulkItem(t, out, alice)["code"])

	// Invitations: only accounts that have not chosen a password, and the
	// answer never carries a link.
	carol := e.activated(t, at, "carol")
	before := len(e.notifier.kinds(domain.NotificationAccountInvite))
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "resend_invite", "ids": []string{alice, carol}})
	requireBulk(t, status, out, 1, 1, 0)
	require.Equal(t, "already_activated", bulkItem(t, out, carol)["code"])
	require.Len(t, e.notifier.kinds(domain.NotificationAccountInvite), before+1)
	raw, _ := json.Marshal(out)
	require.NotContains(t, string(raw), "token=")

	// Locked accounts: the filter of the list, then the bulk unlock.
	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	row, err := e.users.GetByRealmAndUsername(ctx, realm.ID, "bob")
	require.NoError(t, err)
	require.NoError(t, e.ent.User.UpdateOneID(row.ID).SetLockedUntil(e.clock.Now().Add(time.Hour)).Exec(ctx))
	status, list := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/users?locked=true", nil)
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 1, list["total"])
	require.Equal(t, bob, list["items"].([]any)[0].(map[string]any)["id"])
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "unlock", "ids": []string{alice, bob}})
	requireBulk(t, status, out, 1, 1, 0)
	require.Equal(t, "not_locked", bulkItem(t, out, alice)["code"])
	status, list = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/users?locked=true", nil)
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 0, list["total"])

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "delete", "ids": []string{alice, bob}})
	requireBulk(t, status, out, 2, 0, 0)
	_, err = e.users.GetByRealmAndUsername(ctx, realm.ID, "bob")
	require.ErrorIs(t, err, repository.ErrNotFound)
}

func TestAdmin_Integration_BulkGuards(t *testing.T) {
	e, at := userImportEnv(t)
	const master = "/api/v1/realms/master"

	status, list := e.call(t, at, http.MethodGet, master+"/users?q=root", nil)
	require.Equal(t, http.StatusOK, status)
	root := list["items"].([]any)[0].(map[string]any)["id"].(string)

	// Your own account is left out of every action, in the master realm.
	for _, action := range []string{"suspend", "delete", "unlock"} {
		status, out := e.call(t, at, http.MethodPost, master+"/users/bulk", map[string]any{"action": action, "ids": []string{root}})
		requireBulk(t, status, out, 0, 1, 0)
		require.Equal(t, "self_change", bulkItem(t, out, root)["code"], action)
	}
	status, out := e.call(t, at, http.MethodPost, master+"/sessions/bulk", map[string]any{"action": "revoke_users", "ids": []string{root}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "self_change", bulkItem(t, out, root)["code"])

	// And so is the session the call comes from.
	status, sessions := e.call(t, at, http.MethodGet, master+"/sessions", nil)
	require.Equal(t, http.StatusOK, status)
	own := sessions["items"].([]any)[0].(map[string]any)["id"].(string)
	status, out = e.call(t, at, http.MethodPost, master+"/sessions/bulk", map[string]any{"action": "revoke", "ids": []string{own}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "own_session", bulkItem(t, out, own)["code"])
	status, _ = e.call(t, at, http.MethodGet, master+"/users", nil)
	require.Equal(t, http.StatusOK, status, "still signed in")

	// Like every change, a bulk action needs a recent second factor.
	status, out = e.call(t, at, http.MethodPatch, master+"/settings", map[string]any{"mfa_step_up_max_age_minutes": 1})
	require.Equal(t, http.StatusOK, status, "%v", out)
	e.clock.Advance(2 * time.Minute)
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{"x"}})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "step_up_required", out["error"])
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/sessions/bulk", map[string]any{"action": "revoke", "ids": []string{"x"}})
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "step_up_required", out["error"])
}

func TestAdmin_Integration_BulkSessions(t *testing.T) {
	e, at := userImportEnv(t)
	const base = "/api/v1/realms/demo/sessions"
	alice, bob := e.invite(t, at, "alice"), e.invite(t, at, "bob")
	first, second := e.session(t, alice, "203.0.113.7"), e.session(t, bob, "203.0.113.7")
	third := e.session(t, bob, "198.51.100.1")

	// "Every session of this IP": the filter gives the selection.
	status, list := e.call(t, at, http.MethodGet, base+"?ip=203.0.113.7", nil)
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 2, list["total"])

	status, out := e.call(t, at, http.MethodPost, base+"/bulk", map[string]any{"action": "revoke", "ids": []string{first.ID, second.ID, "ghost"}})
	requireBulk(t, status, out, 2, 1, 0)
	require.Equal(t, "alice", bulkItem(t, out, first.ID)["label"])
	require.Equal(t, "not_found", bulkItem(t, out, "ghost")["code"])

	status, out = e.call(t, at, http.MethodPost, base+"/bulk", map[string]any{"action": "revoke_users", "ids": []string{alice, bob}})
	requireBulk(t, status, out, 1, 1, 0)
	require.Equal(t, "no_session", bulkItem(t, out, alice)["code"])
	_, err := e.sessions.GetActive(context.Background(), third.ID)
	require.Error(t, err, "bob is signed out")

	status, out = e.call(t, at, http.MethodPost, base+"/bulk", map[string]any{"action": "nope", "ids": []string{alice}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
}

func TestAdmin_Integration_ForcedPasswordReset(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	alice := e.activated(t, at, "alice")
	invited := e.invite(t, at, "bob")
	suspended := e.activated(t, at, "carol")
	status, out := e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{suspended}})
	requireBulk(t, status, out, 1, 0, 0)
	live := e.session(t, alice, "203.0.113.7")

	const login = "/r/demo/auth/login"
	signIn := func(password string) (int, map[string]any) {
		return e.postIdP(t, login, map[string]any{"identifier": "alice", "password": password})
	}
	status, _ = signIn(adminPassword)
	require.Equal(t, http.StatusOK, status)

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "force_password_reset", "ids": []string{alice, invited, suspended}})
	requireBulk(t, status, out, 1, 2, 0)
	require.Equal(t, "no_password", bulkItem(t, out, invited)["code"])
	require.Equal(t, "not_active", bulkItem(t, out, suspended)["code"])

	// Signed out everywhere, the entry under the operation.
	_, err := e.sessions.GetActive(ctx, live.ID)
	require.Error(t, err)
	status, entries := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?operation="+out["operation_id"].(string), nil)
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 1, entries["total"])
	require.Equal(t, audit.UserPasswordResetForced, entries["items"].([]any)[0].(map[string]any)["action"])

	// Asking twice sends no second link.
	status, again := e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "force_password_reset", "ids": []string{alice}})
	requireBulk(t, status, again, 0, 1, 0)
	require.Equal(t, "already_required", bulkItem(t, again, alice)["code"])

	// The state shows only to who knows the password, and the password opens nothing.
	status, body := signIn("not the password at all")
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_credentials", body["error"])
	status, body = signIn(adminPassword)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "password_change_required", body["error"])

	status, detail := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/users/"+alice, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, detail["must_change_password"])

	// The way out is the e-mail, and the old password does not count.
	mails := e.notifier.kinds(domain.NotificationPasswordResetRequired)
	require.Len(t, mails, 1)
	require.Equal(t, alice, mails[0].UserID)
	require.Empty(t, mails[0].IPAddress, "the administrator's address is not for the user")
	reset := "/r/demo/auth/reset-password"
	status, body = e.postIdP(t, reset, map[string]any{"token": mails[0].ResetToken, "password": adminPassword})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "password_unchanged", body["error"])
	status, body = e.postIdP(t, reset, map[string]any{"token": mails[0].ResetToken, "password": "a brand new passphrase"})
	require.Equal(t, http.StatusOK, status, "%v", body)

	status, detail = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/users/"+alice, nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, false, detail["must_change_password"])
	status, _ = signIn("a brand new passphrase")
	require.Equal(t, http.StatusOK, status)
}

// Without e-mail nobody could get out of a forced reset, and an invitation
// could not reach anybody: the accounts are left alone.
func TestAdmin_Integration_BulkWithoutEmail(t *testing.T) {
	e, at := userImportEnv(t, func(d *service.AdminDeps) { d.EmailEnabled = false })
	alice, bob := e.activated(t, at, "alice"), e.invite(t, at, "bob")

	status, out := e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "force_password_reset", "ids": []string{alice}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "email_disabled", bulkItem(t, out, alice)["code"])
	status, body := e.postIdP(t, "/r/demo/auth/login", map[string]any{"identifier": "alice", "password": adminPassword})
	require.Equal(t, http.StatusOK, status, "%v", body)

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "resend_invite", "ids": []string{bob}})
	requireBulk(t, status, out, 0, 1, 0)
	require.Equal(t, "email_disabled", bulkItem(t, out, bob)["code"])
}
