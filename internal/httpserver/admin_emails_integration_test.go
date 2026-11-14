package httpserver_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/storage/entstore"
)

// B-13 in the Admin API: the verified state of an address, and the
// verification e-mail.
func TestAdmin_Integration_EmailVerified(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users", map[string]any{
		"email": "ivan@example.test", "send_email": true,
	})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	user := out["user"].(map[string]any)
	id := user["id"].(string)
	require.Equal(t, false, user["email_verified"])
	path := "/api/v1/realms/demo/users/" + id

	status, out = e.call(t, at, http.MethodPatch, path, map[string]any{"email_verified": true})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Equal(t, true, out["email_verified"])
	require.NotNil(t, out["email_verified_at"])

	// A new address is not verified.
	status, out = e.call(t, at, http.MethodPatch, path, map[string]any{"email": "ivan@new.example"})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Equal(t, false, out["email_verified"])

	// The profile key is no longer the verified state.
	status, out = e.call(t, at, http.MethodPatch, path, map[string]any{"profile": map[string]any{"email_verified": true}})
	require.Equal(t, http.StatusBadRequest, status, "%v", out)

	// The verification e-mail: queued, audited as the administrator's, once a minute.
	status, out = e.call(t, at, http.MethodPost, path+"/email-verification", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	events := e.notifier.kinds(domain.NotificationEmailVerification)
	require.Len(t, events, 1)
	require.Equal(t, id, events[0].UserID)
	require.NotEmpty(t, events[0].ResetToken)
	status, out = e.call(t, at, http.MethodPost, path+"/email-verification", nil)
	require.Equal(t, http.StatusConflict, status, "%v", out)
	require.Equal(t, "too_soon", out["error"])

	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	all, err := e.audit.ListByRealm(ctx, realm.ID)
	require.NoError(t, err)
	var sent []*domain.AuditLog
	for _, l := range all {
		if l.Action == audit.UserEmailVerificationSent && l.TargetUserID == id {
			sent = append(sent, l)
		}
	}
	require.Len(t, sent, 1, "one entry, the administrator's")
	require.Equal(t, domain.AuditActorAdmin, sent[0].ActorType)
}

// B-12 in the Admin API: the e-mails of an account, and "send again".
func TestAdmin_Integration_ResendEmail(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users", map[string]any{"email": "jade@example.test"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	id := out["user"].(map[string]any)["id"].(string)
	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	outbox := entstore.NewEmailOutboxRepository(e.ent)
	now := time.Now()
	add := func(kind domain.NotificationKind, status domain.OutboxStatus, linkExpires time.Time) string {
		row := &domain.OutboxEmail{
			ID: uuid.NewString(), RealmID: realm.ID, UserID: id, Kind: kind, Status: status,
			Event:         domain.NotificationEvent{Kind: kind, ExpiresAt: linkExpires},
			NextAttemptAt: now.Add(time.Hour), Deadline: now.Add(-time.Minute), CreatedAt: now,
			LastError: "gave up after 18 attempts: dial tcp: connection refused",
		}
		require.NoError(t, outbox.Create(ctx, row))
		return row.ID
	}
	failed := add(domain.NotificationPasswordChanged, domain.OutboxFailed, time.Time{})
	sent := add(domain.NotificationPasswordChanged, domain.OutboxSent, time.Time{})
	expired := add(domain.NotificationAccountInvite, domain.OutboxFailed, now.Add(-time.Minute))
	path := "/api/v1/realms/demo/users/" + id

	status, out = e.call(t, at, http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	emails := out["emails"].([]any)
	require.Len(t, emails, 3)
	byID := map[string]map[string]any{}
	for _, m := range emails {
		byID[m.(map[string]any)["id"].(string)] = m.(map[string]any)
	}
	require.Equal(t, true, byID[failed]["can_resend"])
	require.Equal(t, false, byID[sent]["can_resend"])
	require.Equal(t, false, byID[expired]["can_resend"], "its link is dead")
	require.Contains(t, byID[failed]["last_error"], "connection refused")

	status, out = e.call(t, at, http.MethodPost, path+"/emails/"+failed+"/resend", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	row, err := outbox.Get(ctx, failed)
	require.NoError(t, err)
	require.Equal(t, domain.OutboxPending, row.Status)
	require.Zero(t, row.Attempts)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), row.Deadline, time.Minute)

	status, out = e.call(t, at, http.MethodPost, path+"/emails/"+sent+"/resend", nil)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "email_sent", out["error"])
	status, out = e.call(t, at, http.MethodPost, path+"/emails/"+expired+"/resend", nil)
	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "link_expired", out["error"])
	status, _ = e.call(t, at, http.MethodPost, path+"/emails/"+uuid.NewString()+"/resend", nil)
	require.Equal(t, http.StatusNotFound, status)

	all, err := e.audit.ListByRealm(ctx, realm.ID)
	require.NoError(t, err)
	n := 0
	for _, l := range all {
		if l.Action == audit.NotificationRequeued {
			n++
			require.Equal(t, failed, l.Details["email_id"])
		}
	}
	require.Equal(t, 1, n)
}

// B-12 in an import's report: what became of each e-mailed invitation, and
// "send these invitations again" for those that did not get through.
func TestAdmin_Integration_ImportInvitationDelivery(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	const base = "/api/v1/realms/demo/users"
	status, started := e.call(t, at, http.MethodPost, base+"/imports", map[string]any{
		"csv": "email\nkim@example.test\nlou@example.test\nmax@example.test\n", "send_email": true,
	})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	id := started["id"].(string)
	waitForImport(t, e, at, "demo", id)
	require.Len(t, e.notifier.kinds(domain.NotificationAccountInvite), 3)

	// What the outbox would hold: kim's sent, lou's given up, max's waiting.
	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	outbox := entstore.NewEmailOutboxRepository(e.ent)
	userID := map[string]string{}
	for _, name := range []string{"kim", "lou", "max"} {
		u, err := e.users.GetByRealmAndEmail(ctx, realm.ID, name+"@example.test")
		require.NoError(t, err)
		userID[name] = u.ID
	}
	now := time.Now()
	for name, st := range map[string]domain.OutboxStatus{"kim": domain.OutboxSent, "lou": domain.OutboxFailed, "max": domain.OutboxPending} {
		require.NoError(t, outbox.Create(ctx, &domain.OutboxEmail{
			ID: uuid.NewString(), RealmID: realm.ID, UserID: userID[name], Kind: domain.NotificationAccountInvite, Status: st,
			Event:         domain.NotificationEvent{Kind: domain.NotificationAccountInvite, ExpiresAt: now.Add(time.Hour)},
			NextAttemptAt: now.Add(time.Hour), Deadline: now.Add(time.Hour), CreatedAt: now,
		}))
	}

	status, job := e.call(t, at, http.MethodGet, base+"/imports/"+id, nil)
	require.Equal(t, http.StatusOK, status, "%v", job)
	require.EqualValues(t, 1, job["email_failed"])
	require.EqualValues(t, 1, job["email_pending"])
	delivery := map[string]any{}
	for _, r := range job["rows"].([]any) {
		row := r.(map[string]any)
		delivery[row["email"].(string)] = row["delivery"]
	}
	require.Equal(t, map[string]any{"kim@example.test": "sent", "lou@example.test": "failed", "max@example.test": "pending"}, delivery)

	status, out := e.call(t, at, http.MethodPost, base+"/imports/"+id+"/resend-invitations", nil)
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.EqualValues(t, 1, out["sent"], "lou only")
	invites := e.notifier.kinds(domain.NotificationAccountInvite)
	require.Len(t, invites, 4)
	require.Equal(t, userID["lou"], invites[3].UserID)
}
