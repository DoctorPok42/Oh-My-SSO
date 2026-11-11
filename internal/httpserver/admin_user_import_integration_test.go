package httpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// userImportEnv: an instance with an administrator and a realm "demo" that
// has a group "staff" and a role "support".
func userImportEnv(t *testing.T, options ...func(*service.AdminDeps)) (e *adminTestEnv, at string) {
	t.Helper()
	e = setupAdminTestEnv(t, append([]func(*service.AdminDeps){func(d *service.AdminDeps) { d.EmailEnabled = true }}, options...)...)
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
	at = e.signIn(t, console, "root", &secret).AccessToken

	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms", map[string]any{"name": "demo", "display_name": "Demo Corp"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/groups", map[string]any{"name": "staff"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/roles", map[string]any{"name": "support"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	return e, at
}

// waitForImport polls the Admin API like the console does.
func waitForImport(t *testing.T, e *adminTestEnv, at, realm, id string) map[string]any {
	t.Helper()
	var job map[string]any
	require.Eventually(t, func() bool {
		status, out := e.call(t, at, http.MethodGet, "/api/v1/realms/"+realm+"/users/imports/"+id, nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		job = out
		return out["status"] != "running"
	}, 15*time.Second, 20*time.Millisecond)
	return job
}

func TestAdmin_Integration_UserImport(t *testing.T) {
	e, at := userImportEnv(t)
	const base = "/api/v1/realms/demo/users"

	status, out := e.call(t, at, http.MethodPost, base, map[string]any{"email": "taken@example.test", "send_email": false})
	require.Equal(t, http.StatusCreated, status, "%v", out)

	file := strings.Join([]string{
		"email,username,name,groups,roles,password",
		"alice@example.test,alice,Alice Moreau,staff,support,hunter2-alice",
		"bob@example.test,,,,,hunter2-bob",
		"taken@example.test,,,,,hunter2-taken",
		"ALICE@example.test,other,,,,hunter2-again",
		"carol@example.test,carol,,nope,,hunter2-carol",
		"not an address,,,,,hunter2-dave",
	}, "\n") + "\n"

	// The preview tells what would happen, and changes nothing.
	status, preview := e.call(t, at, http.MethodPost, base+"/imports/preview", map[string]any{"csv": file})
	require.Equal(t, http.StatusOK, status, "%v", preview)
	require.EqualValues(t, 6, preview["total"])
	require.EqualValues(t, 2, preview["valid"])
	require.EqualValues(t, 4, preview["invalid"])
	require.Equal(t, []any{"password"}, preview["ignored_columns"])
	require.Equal(t, []any{"name"}, preview["profile_columns"])
	raw, _ := json.Marshal(preview)
	require.NotContains(t, string(raw), "hunter2", "a password never comes back")
	rows := preview["rows"].([]any)
	require.Equal(t, "valid", rows[0].(map[string]any)["status"])
	require.EqualValues(t, 2, rows[0].(map[string]any)["line"])
	require.Equal(t, "bob", rows[1].(map[string]any)["username"], "the default username is shown")
	require.Contains(t, rows[2].(map[string]any)["error"], "already used")
	require.Contains(t, rows[3].(map[string]any)["error"], "line 2", "two lines for one person")
	require.Contains(t, rows[4].(map[string]any)["error"], `no group "nope"`)
	status, list := e.call(t, at, http.MethodGet, base, nil)
	require.Equal(t, http.StatusOK, status)
	require.EqualValues(t, 1, list["total"], "a preview writes nothing")

	// A file that cannot be read is refused at once.
	status, out = e.call(t, at, http.MethodPost, base+"/imports", map[string]any{"csv": "username\nalice\n"})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)
	require.Equal(t, "import_header", out["error"])

	// The import: in the background, the valid lines only.
	status, started := e.call(t, at, http.MethodPost, base+"/imports", map[string]any{
		"csv": file, "file_name": `C:\exports\hires.csv`, "send_email": true, "notify_when_done": true,
	})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	require.Equal(t, "running", started["status"])
	id := started["id"].(string)

	job := waitForImport(t, e, at, "demo", id)
	require.Equal(t, "completed", job["status"], "%v", job)
	require.Equal(t, "hires.csv", job["file_name"])
	require.EqualValues(t, 6, job["processed"])
	require.EqualValues(t, 2, job["created"])
	require.EqualValues(t, 4, job["failed"])
	require.EqualValues(t, 0, job["without_email"])
	raw, _ = json.Marshal(job)
	require.NotContains(t, string(raw), "hunter2")
	require.NotContains(t, string(raw), "user_id", "the report has no internal id")
	rows = job["rows"].([]any)
	require.Len(t, rows, 6)
	require.Equal(t, "created", rows[0].(map[string]any)["status"])
	require.Equal(t, true, rows[0].(map[string]any)["emailed"])
	require.Equal(t, "failed", rows[2].(map[string]any)["status"])

	// The accounts are invitations: no password, profile and rights set.
	realm, err := e.admin.RealmByName(context.Background(), "demo")
	require.NoError(t, err)
	alice, err := e.users.GetByRealmAndUsername(context.Background(), realm.ID, "alice")
	require.NoError(t, err)
	require.Empty(t, alice.PasswordHash)
	detail, err := e.admin.GetUser(context.Background(), realm, alice.ID)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{"name": "Alice Moreau"}, detail.Profile, "the password column is not an attribute")
	require.Len(t, detail.Groups, 1)
	require.Equal(t, "staff", detail.Groups[0].Name)
	require.Len(t, detail.Roles, 1)
	require.Equal(t, "support", detail.Roles[0].Name)

	// One invitation per account, then one e-mail to the administrator, in
	// the master realm: that is where the account is.
	require.Len(t, e.notifier.kinds(domain.NotificationAccountInvite), 2)
	done := e.notifier.kinds(domain.NotificationUserImportFinished)
	require.Len(t, done, 1)
	master, err := e.admin.RealmByName(context.Background(), service.MasterRealmName)
	require.NoError(t, err)
	root, err := e.users.GetByRealmAndUsername(context.Background(), master.ID, "root")
	require.NoError(t, err)
	require.Equal(t, master.ID, done[0].RealmID)
	require.Equal(t, root.ID, done[0].UserID)
	require.Equal(t, "demo", done[0].ImportRealm)
	require.Equal(t, 6, done[0].ImportTotal)
	require.Equal(t, 2, done[0].ImportCreated)
	require.Equal(t, 4, done[0].ImportFailed)
	require.False(t, done[0].ImportInterrupted)
	require.False(t, done[0].QuietAudit, "the administrator's e-mail is an event of its own")
	require.Equal(t, adminConsoleURL+"/r/demo/users?import="+id, done[0].ImportURL)

	logs, err := e.audit.ListByResource(context.Background(), "UserImportJob", id)
	require.NoError(t, err)
	actions := map[string]domain.AuditLogLevel{}
	var summary map[string]interface{}
	for _, l := range logs {
		actions[l.Action] = l.Level
		if l.Action == audit.UserImportFinished {
			summary = l.Details
		}
	}
	require.Equal(t, domain.AuditLogInfo, actions[audit.UserImportStarted])
	require.Equal(t, domain.AuditLogWarning, actions[audit.UserImportFinished], "some lines were refused")

	// The audit log gets the import as a whole, not three entries per person:
	// only the account invited by hand above has entries of its own...
	all, err := e.audit.ListByRealm(context.Background(), realm.ID)
	require.NoError(t, err)
	perUser := map[string]int{}
	for _, l := range all {
		perUser[l.Action]++
	}
	require.Equal(t, 1, perUser[audit.UserInvited])
	require.Equal(t, 1, perUser[audit.UserActivationLinkSent])
	for _, invite := range e.notifier.kinds(domain.NotificationAccountInvite) {
		require.True(t, invite.QuietAudit, "notification.sent stays out of the log, unless the e-mail fails")
	}
	// ...and the summary keeps what those entries said, rights included.
	users := summary["created_users"].([]interface{})
	require.Len(t, users, 2)
	first := users[0].(map[string]interface{})
	require.Equal(t, "alice", first["username"])
	require.Equal(t, "alice@example.test", first["email"])
	require.Equal(t, []interface{}{"staff"}, first["groups"])
	require.Equal(t, []interface{}{"support"}, first["roles"])

	// Importing the same file again creates nothing: an import never merges.
	status, again := e.call(t, at, http.MethodPost, base+"/imports", map[string]any{"csv": file})
	require.Equal(t, http.StatusAccepted, status, "%v", again)
	job = waitForImport(t, e, at, "demo", again["id"].(string))
	require.EqualValues(t, 0, job["created"])
	require.EqualValues(t, 6, job["failed"])
	require.Len(t, e.notifier.kinds(domain.NotificationAccountInvite), 2)
	require.Len(t, e.notifier.kinds(domain.NotificationUserImportFinished), 1, "nobody asked for this one")

	// Another realm does not see this import.
	status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/master/users/imports/"+id, nil)
	require.Equal(t, http.StatusNotFound, status, "%v", out)
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/master/users/imports/"+id+"/activation-links", nil)
	require.Equal(t, http.StatusNotFound, status, "%v", out)

	// The list: the newest first, without rows.
	status, imports := e.call(t, at, http.MethodGet, base+"/imports", nil)
	require.Equal(t, http.StatusOK, status)
	items := imports["items"].([]any)
	require.Len(t, items, 2)
	require.Equal(t, again["id"], items[0].(map[string]any)["id"])
	require.NotContains(t, items[0], "rows")
}

// Without e-mails, the links are made when asked for: none is stored.
func TestAdmin_Integration_UserImportActivationLinks(t *testing.T) {
	e, at := userImportEnv(t)
	const base = "/api/v1/realms/demo/users"

	status, started := e.call(t, at, http.MethodPost, base+"/imports", map[string]any{
		"csv": "email\nalice@example.test\nbob@example.test\n", "send_email": false,
	})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	id := started["id"].(string)
	job := waitForImport(t, e, at, "demo", id)
	require.EqualValues(t, 2, job["without_email"])
	require.Empty(t, e.notifier.kinds(domain.NotificationAccountInvite))

	rowsInDB, err := entstore.NewUserImportRepository(e.ent).GetByID(context.Background(), id)
	require.NoError(t, err)
	raw, _ := json.Marshal(rowsInDB)
	require.NotContains(t, string(raw), "reset-password", "no link in the database")

	status, out := e.call(t, at, http.MethodPost, base+"/imports/"+id+"/activation-links", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	links := out["links"].([]any)
	require.Len(t, links, 2)
	first := links[0].(map[string]any)
	require.Equal(t, "alice@example.test", first["email"])

	// A second call replaces them: the first link of bob stops working...
	status, out = e.call(t, at, http.MethodPost, base+"/imports/"+id+"/activation-links", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	links = out["links"].([]any)
	require.Len(t, links, 2)

	// ...and an account that chose its password is left alone.
	e.activate(t, links[0].(map[string]any)["activation_url"].(string))
	status, out = e.call(t, at, http.MethodPost, base+"/imports/"+id+"/activation-links", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	links = out["links"].([]any)
	require.Len(t, links, 1)
	require.Equal(t, "bob@example.test", links[0].(map[string]any)["email"])

	// One entry per download, not one per link.
	realm, err := e.admin.RealmByName(context.Background(), "demo")
	require.NoError(t, err)
	logs, err := e.audit.ListByRealm(context.Background(), realm.ID)
	require.NoError(t, err)
	var downloads, perUser int
	for _, l := range logs {
		switch {
		case l.Action == audit.UserActivationLinkSent && l.ResourceType == "UserImportJob":
			downloads++
		case l.Action == audit.UserActivationLinkSent || l.Action == audit.UserInvited:
			perUser++
		}
	}
	require.Equal(t, 3, downloads)
	require.Zero(t, perUser)
}

// One import at a time in a realm, and one lost by a crash ends by itself.
func TestAdmin_Integration_UserImportReaper(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	repo := entstore.NewUserImportRepository(e.ent)
	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	master, err := e.admin.RealmByName(ctx, service.MasterRealmName)
	require.NoError(t, err)
	root, err := e.users.GetByRealmAndUsername(ctx, master.ID, "root")
	require.NoError(t, err)

	// The row a process that died leaves behind.
	lost, err := repo.Create(ctx, repository.CreateUserImportParams{
		RealmID: realm.ID, FileName: "lost.csv", RequestedBy: root.ID, RequestedByName: "root",
		RequestedByRealm: master.ID, NotifyWhenDone: true, Total: 500,
	})
	require.NoError(t, err)

	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users/imports", map[string]any{"csv": "email\na@example.test\n"})
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "import_running", out["error"])

	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.admin.RunUserImportReaper(stop, 20*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	got, err := repo.GetByID(ctx, lost.ID)
	require.NoError(t, err)
	require.Equal(t, domain.UserImportRunning, got.Status, "a recent import is not lost")

	e.clock.Advance(11 * time.Minute)
	require.Eventually(t, func() bool {
		return len(e.notifier.kinds(domain.NotificationUserImportFinished)) == 1
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	got, err = repo.GetByID(ctx, lost.ID)
	require.NoError(t, err)
	require.Equal(t, domain.UserImportInterrupted, got.Status)
	require.NotNil(t, got.FinishedAt)
	mail := e.notifier.kinds(domain.NotificationUserImportFinished)[0]
	require.True(t, mail.ImportInterrupted)
	require.Equal(t, "demo", mail.ImportRealm)
	require.Equal(t, root.ID, mail.UserID)
}

// A server that stops ends its import at the current line, and says so.
func TestAdmin_Integration_UserImportInterrupted(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()

	reached, release := make(chan struct{}, 3), make(chan struct{})
	e.notifier.onNotify = func(ev domain.NotificationEvent) {
		if ev.Kind == domain.NotificationAccountInvite {
			reached <- struct{}{}
			<-release
		}
	}
	status, started := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users/imports", map[string]any{
		"csv": "email\na@example.test\nb@example.test\nc@example.test\n", "send_email": true, "notify_when_done": true,
	})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	select {
	case <-reached: // the first line reaches the e-mail
	case <-time.After(10 * time.Second):
		t.Fatal("the first line never reached the e-mail")
	}

	stopped := make(chan struct{})
	stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	go func() { e.admin.StopUserImports(stopCtx); close(stopped) }()
	// Not a sleep: on a slow runner (CI, -race) the stop could come after the
	// release, and the import would then run the next lines too.
	e.awaitStopping(t, at, "/api/v1/realms/demo/users/imports", map[string]any{"csv": "email\nd@example.test\n"})
	close(release) // the line in progress finishes
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("StopUserImports did not return")
	}

	job := waitForImport(t, e, at, "demo", started["id"].(string))
	require.Equal(t, "interrupted", job["status"], "%v", job)
	require.EqualValues(t, 1, job["processed"])
	require.EqualValues(t, 1, job["created"])
	mail := e.notifier.kinds(domain.NotificationUserImportFinished)
	require.Len(t, mail, 1)
	require.True(t, mail[0].ImportInterrupted)

	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	_, err = e.users.GetByRealmAndEmail(ctx, realm.ID, "a@example.test")
	require.NoError(t, err)
	_, err = e.users.GetByRealmAndEmail(ctx, realm.ID, "b@example.test")
	require.ErrorIs(t, err, repository.ErrNotFound, "the next lines are left alone")

	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users/imports", map[string]any{"csv": "email\nd@example.test\n"})
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "stopping", out["error"])
}
