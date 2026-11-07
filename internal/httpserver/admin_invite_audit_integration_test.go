package httpserver_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/storage/entstore"
)

type stubSender struct{ err error }

func (s stubSender) Send(context.Context, string, notify.Template, notify.Data) error { return s.err }

// Only an import is grouped in the audit log. An account invited on its own
// keeps every entry: the invitation and the link by the administrator, the
// e-mail by the system. The event goes through the real dispatcher.
func TestAdmin_Integration_SingleInviteStaysAudited(t *testing.T) {
	e, at := userImportEnv(t)
	ctx := context.Background()
	realm, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)
	master, err := e.admin.RealmByName(ctx, service.MasterRealmName)
	require.NoError(t, err)
	root, err := e.users.GetByRealmAndUsername(ctx, master.ID, "root")
	require.NoError(t, err)

	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users", map[string]any{
		"email": "dana@example.test", "send_email": true,
	})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	require.Equal(t, true, out["emailed"])
	userID := out["user"].(map[string]any)["id"].(string)

	about := func(action string) []*domain.AuditLog {
		logs, err := e.audit.ListByRealm(ctx, realm.ID)
		require.NoError(t, err)
		var found []*domain.AuditLog
		for _, l := range logs {
			if l.Action == action && l.TargetUserID == userID {
				found = append(found, l)
			}
		}
		return found
	}

	invited := about(audit.UserInvited)
	require.Len(t, invited, 1)
	require.Equal(t, domain.AuditActorAdmin, invited[0].ActorType)
	require.Equal(t, root.ID, invited[0].UserID)
	require.Equal(t, "User", invited[0].ResourceType)
	require.Equal(t, "dana@example.test", invited[0].Details["email"])

	link := about(audit.UserActivationLinkSent)
	require.Len(t, link, 1)
	require.Equal(t, domain.AuditActorAdmin, link[0].ActorType)
	require.Equal(t, true, link[0].Details["emailed"])

	// The e-mail: written by the dispatcher, whose actor is the system.
	events := e.notifier.kinds(domain.NotificationAccountInvite)
	require.Len(t, events, 1)
	require.False(t, events[0].QuietAudit)
	dispatcher := func(sender notify.EmailSender) *notify.Dispatcher {
		return notify.NewDispatcher(notify.DispatcherConfig{PublicURL: e.idp.URL, MaxAttempts: 1}, notify.DispatcherDeps{
			Sender: sender, Users: e.users, Realms: entstore.NewRealmRepository(e.ent), Audit: e.audit,
		})
	}
	require.NoError(t, dispatcher(stubSender{}).Process(ctx, events[0]))
	sent := about(audit.NotificationSent)
	require.Len(t, sent, 1)
	require.Equal(t, domain.AuditActorSystem, sent[0].ActorType)
	require.Empty(t, sent[0].UserID, "the server sends, nobody acts")
	require.Equal(t, "sent", sent[0].Details["status"])
	require.Equal(t, "dana@example.test", sent[0].Details["to"])
	require.Equal(t, "account_invite", sent[0].Details["template"])

	// A new link for the same account, by e-mail too.
	status, out = e.call(t, at, http.MethodPost, "/api/v1/realms/demo/users/"+userID+"/activation-link", map[string]any{"send_email": true})
	require.Equal(t, http.StatusOK, status, "%v", out)
	require.Len(t, about(audit.UserActivationLinkSent), 2)
	events = e.notifier.kinds(domain.NotificationAccountInvite)
	require.Len(t, events, 2)
	require.False(t, events[1].QuietAudit)

	// An e-mail that fails is written too.
	require.Error(t, dispatcher(stubSender{err: errors.New("smtp down")}).Process(ctx, events[1]))
	sent = about(audit.NotificationSent)
	require.Len(t, sent, 2)
	var failed int
	for _, l := range sent {
		if l.Details["status"] == "failed" {
			failed++
			require.Equal(t, domain.AuditActorSystem, l.ActorType)
			require.Equal(t, domain.AuditLogFailure, l.Status)
		}
	}
	require.Equal(t, 1, failed)
}
