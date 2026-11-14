package httpserver_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// A bulk action answers at once and runs in the background: the console
// follows it by its id. While it runs the realm takes no other one, and only
// the administrator who started it reads it.
func TestAdmin_Integration_BulkRunsInTheBackground(t *testing.T) {
	e, at := userImportEnv(t)
	alice, bob := e.invite(t, at, "alice"), e.invite(t, at, "bob")

	// The first invitation waits: the job stays running as long as we want.
	reached, release := make(chan struct{}, 2), make(chan struct{})
	e.notifier.onNotify = func(ev domain.NotificationEvent) {
		if ev.Kind == domain.NotificationAccountInvite {
			reached <- struct{}{}
			<-release
		}
	}
	status, started := e.send(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "resend_invite", "ids": []string{alice, bob}})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	require.Equal(t, "running", started["status"])
	require.EqualValues(t, 2, started["total"])
	require.Equal(t, "resend_invite", started["action"])
	id := started["id"].(string)
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the first item never started")
	}

	// It is followed by its id; the items come with the report.
	status, job := e.send(t, at, http.MethodGet, "/api/v1/realms/demo/bulk-jobs/"+id, nil)
	require.Equal(t, http.StatusOK, status, "%v", job)
	require.Equal(t, "running", job["status"])
	require.Empty(t, job["items"])

	// One at a time in a realm; another realm is free.
	status, out := e.send(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{alice}})
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "bulk_running", out["error"])
	status, out = e.send(t, at, http.MethodPost, "/api/v1/realms/master/sessions/bulk", map[string]any{"action": "revoke", "ids": []string{"x"}})
	require.NotEqual(t, http.StatusConflict, status, "%v", out)

	// A job belongs to its realm.
	status, out = e.send(t, at, http.MethodGet, "/api/v1/realms/master/bulk-jobs/"+id, nil)
	require.Equal(t, http.StatusNotFound, status, "%v", out)
	status, out = e.send(t, at, http.MethodGet, "/api/v1/realms/demo/bulk-jobs/nope", nil)
	require.Equal(t, http.StatusNotFound, status, "%v", out)

	close(release)
	status, report := e.awaitBulk(t, at, bulkUsers, started)
	requireBulk(t, status, report, 2, 0, 0)
	require.Equal(t, "completed", report["status"])
	require.EqualValues(t, 2, report["processed"])
	require.EqualValues(t, 0, report["not_run"])
	require.Len(t, report["items"], 2)
	require.NotNil(t, report["finished_at"])

	// Over: the realm takes the next one.
	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{alice}})
	requireBulk(t, status, out, 1, 0, 0)
}

// A server that stops (a deployment) finishes the item it is on, leaves the
// others alone and says which: the report lists them, and the audit log
// carries an entry under the operation.
func TestAdmin_Integration_BulkInterrupted(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	alice, bob, carol := e.invite(t, at, "alice"), e.invite(t, at, "bob"), e.invite(t, at, "carol")

	reached, release := make(chan struct{}, 3), make(chan struct{})
	e.notifier.onNotify = func(ev domain.NotificationEvent) {
		if ev.Kind == domain.NotificationAccountInvite {
			reached <- struct{}{}
			<-release
		}
	}
	status, started := e.send(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "resend_invite", "ids": []string{alice, bob, carol}})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the first item never started")
	}

	stopped := make(chan struct{})
	stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	go func() { e.admin.StopBulkJobs(stopCtx); close(stopped) }()
	// Not a sleep: on a slow runner (CI, -race) the stop could come after the
	// release, and the job would then run bob and carol too.
	e.awaitStopping(t, at, bulkUsers, map[string]any{"action": "suspend", "ids": []string{alice}})
	close(release) // the item in progress finishes
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("StopBulkJobs did not return")
	}

	status, job := e.awaitBulk(t, at, bulkUsers, started)
	require.Equal(t, http.StatusOK, status, "%v", job)
	require.Equal(t, "interrupted", job["status"], "%v", job)
	require.EqualValues(t, 1, job["processed"])
	require.EqualValues(t, 1, job["done"])
	require.EqualValues(t, 2, job["not_run"])
	require.Equal(t, "done", bulkItem(t, job, alice)["status"])
	for _, id := range []string{bob, carol} {
		item := bulkItem(t, job, id)
		require.Equal(t, "not_run", item["status"], "%v", item)
		require.NotEmpty(t, item["message"], "the reader is told why")
	}
	require.Len(t, e.notifier.kinds(domain.NotificationAccountInvite), 1, "the others got nothing")

	// The trace: one entry, under the operation, naming what was left.
	op := job["operation_id"].(string)
	status, entries := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?operation="+op+"&action="+audit.BulkInterrupted, nil)
	require.Equal(t, http.StatusOK, status, "%v", entries)
	require.EqualValues(t, 1, entries["total"], "%v", entries)
	details := entries["items"].([]any)[0].(map[string]any)["details"].(map[string]any)
	require.EqualValues(t, 2, details["not_processed"])
	require.ElementsMatch(t, []any{bob, carol}, details["not_processed_ids"])

	// A stopping server takes no new bulk action.
	status, out := e.send(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{alice}})
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "stopping", out["error"])
}

// awaitStopping waits until the server refuses a new job as "stopping" (POST
// path with body): from then on, the running jobs see the stop at their next
// item. Before, the request is refused as busy (a job runs in the realm), so
// the polling starts nothing.
func (e *adminTestEnv) awaitStopping(t *testing.T, token, path string, body map[string]any) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, out := e.send(t, token, http.MethodPost, path, body)
		require.Equal(t, http.StatusConflict, status, "%v", out)
		if out["error"] == "stopping" {
			return
		}
		require.True(t, time.Now().Before(deadline), "the server never refused as stopping: %v", out)
		time.Sleep(5 * time.Millisecond)
	}
}

// A process that died leaves a running row behind: the reaper finds it by its
// silence, lists what was not done and writes the audit entry.
func TestAdmin_Integration_BulkReaper(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	repo := entstore.NewBulkJobRepository(e.ent)
	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	master, err := e.admin.RealmByName(ctx, "master")
	require.NoError(t, err)
	root, err := e.users.GetByRealmAndUsername(ctx, master.ID, "root")
	require.NoError(t, err)

	// 5 items; the process saved 1 item and a count of 3 before it died.
	ids := []string{"a", "b", "c", "d", "e"}
	lost, err := repo.Create(ctx, repository.CreateBulkJobParams{
		RealmID: realm.ID, Action: "suspend", OperationID: "op_00000000000000aa",
		RequestedBy: root.ID, RequestedByName: "root", RequestedByRealm: master.ID, IDs: ids,
	})
	require.NoError(t, err)
	require.NoError(t, repo.UpdateProgress(ctx, lost.ID, repository.BulkJobProgress{
		Processed: 3, Done: 3, Items: []domain.BulkItem{{ID: "a", Label: "a", Status: domain.BulkItemDone}},
	}))

	status, out := e.send(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{"x"}})
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "bulk_running", out["error"])

	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.admin.RunBulkReaper(stop, 20*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	got, err := repo.GetByID(ctx, lost.ID)
	require.NoError(t, err)
	require.Equal(t, domain.BulkJobRunning, got.Status, "a recent bulk action is not lost")

	e.clock.Advance(3 * time.Minute)
	require.Eventually(t, func() bool {
		got, err = repo.GetByID(ctx, lost.ID)
		return err == nil && got.Status == domain.BulkJobInterrupted && len(got.Items) == len(ids)
	}, 5*time.Second, 10*time.Millisecond)
	// The audit entry comes right after the report: wait for it, stopping
	// the reaper first would race with its write.
	require.Eventually(t, func() bool {
		status, entries := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?operation=op_00000000000000aa", nil)
		return status == http.StatusOK && entries["total"] == float64(1)
	}, 5*time.Second, 20*time.Millisecond)
	cancel()
	require.NotNil(t, got.FinishedAt)
	// b, c ran (the count says 3) but nobody recorded how; d was maybe being
	// done; e was not started.
	var statuses []string
	for _, it := range got.Items {
		statuses = append(statuses, it.Status)
	}
	require.Equal(t, []string{"done", "unknown", "unknown", "unknown", "not_run"}, statuses)

	status, job := e.send(t, at, http.MethodGet, "/api/v1/realms/demo/bulk-jobs/"+lost.ID, nil)
	require.Equal(t, http.StatusOK, status, "%v", job)
	require.EqualValues(t, 4, job["not_run"], "the unknown ones are told apart from the done: %v", job)

	status, entries := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?operation=op_00000000000000aa", nil)
	require.Equal(t, http.StatusOK, status, "%v", entries)
	require.EqualValues(t, 1, entries["total"], "%v", entries)
	require.Equal(t, audit.BulkInterrupted, entries["items"].([]any)[0].(map[string]any)["action"])

	status, out = e.call(t, at, http.MethodPost, bulkUsers, map[string]any{"action": "suspend", "ids": []string{"x"}})
	requireBulk(t, status, out, 0, 1, 0) // the realm is free again
}
