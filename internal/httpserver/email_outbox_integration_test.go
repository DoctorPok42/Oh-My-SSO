package httpserver_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent/emailoutbox"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
)

// B-12: a reset link asked for while the mail server is down is not lost.
// It waits in the outbox, survives a restart of the server, and leaves when
// the mail server answers again. B-13: using that e-mailed link verifies
// the address.
func TestEmailOutbox_SMTPOutageAndRestart(t *testing.T) {
	env := setupResetEnv(t)
	ctx := context.Background()
	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "outage", DisplayName: "Outage Inc"})
	require.NoError(t, err)
	hash, err := service.HashPassword("the old password")
	require.NoError(t, err)
	user, err := env.users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: "frank", Email: "frank@example.test", PasswordHash: hash, Status: domain.UserActive,
	})
	require.NoError(t, err)
	require.Nil(t, user.EmailVerifiedAt)

	smtpDown := errors.New("dial tcp 10.0.0.25:587: connect: connection refused")
	env.mail.setFail(smtpDown)
	status, _, _ := env.post(t, "/r/outage/auth/forgot-password", map[string]string{"identifier": "frank"})
	require.Equal(t, http.StatusAccepted, status)

	// Tried once, failed, waiting for its next attempt.
	var row *struct {
		id       string
		attempts int
	}
	require.Eventually(t, func() bool {
		e, err := env.client.EmailOutbox.Query().Where(emailoutbox.UserID(user.ID)).Only(ctx)
		if err != nil || e.Attempts == 0 || e.LockedUntil != nil {
			return false
		}
		row = &struct {
			id       string
			attempts int
		}{e.ID, e.Attempts}
		return true
	}, 10*time.Second, 20*time.Millisecond)
	e, err := env.client.EmailOutbox.Get(ctx, row.id)
	require.NoError(t, err)
	require.Equal(t, entschema.EmailOutboxPending, e.Status)
	require.Contains(t, e.LastError, "connection refused")
	require.NotContains(t, e.Event, "token=", "the link is sealed, never in clear")
	require.Empty(t, env.mail.mails(notify.TemplatePasswordReset))

	// The server stops; the mail server comes back; a new server starts.
	// Its clock is past the next attempt (30 s), without waiting for it.
	env.dispatcher.Close(ctx)
	env.mail.setFail(nil)
	restarted := env.newDispatcher(func() time.Time { return time.Now().Add(time.Minute) })
	restarted.Start()
	t.Cleanup(func() { restarted.Close(context.Background()) })

	mails := env.mail.waitMails(t, notify.TemplatePasswordReset, 1)
	require.Equal(t, "frank@example.test", mails[0].to)
	e, err = env.client.EmailOutbox.Get(ctx, row.id)
	require.NoError(t, err)
	require.Equal(t, entschema.EmailOutboxSent, e.Status)
	require.Equal(t, row.attempts+1, e.Attempts)

	// One audit entry for the e-mail, at the end: sent, after 2 attempts.
	var entries []*domain.AuditLog
	require.Eventually(t, func() bool {
		entries = auditOf(t, env, realm.ID, "notification.sent")
		return len(entries) > 0
	}, 5*time.Second, 20*time.Millisecond, "written right after the row is marked sent")
	require.Len(t, entries, 1)
	require.Equal(t, "sent", entries[0].Details["status"])
	require.EqualValues(t, 2, entries[0].Details["attempts"])

	// The link reached the address: using it verifies the address.
	status, _, _ = env.post(t, "/r/outage/auth/reset-password", map[string]string{
		"token": tokenFrom(t, mails[0]), "password": "a brand new passphrase",
	})
	require.Equal(t, http.StatusOK, status)
	got, err := env.users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, got.EmailVerifiedAt, "B-13: the e-mailed link proved the address")
}

// B-13: the link of a "confirm your address" e-mail, from the page it opens.
func TestEmailVerification_Page(t *testing.T) {
	env := setupResetEnv(t)
	ctx := context.Background()
	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "verify", DisplayName: "Verify Inc"})
	require.NoError(t, err)
	user, err := env.users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: "gina", Email: "gina@example.test", Status: domain.UserActive,
	})
	require.NoError(t, err)

	_, err = env.verify.Send(ctx, user, service.VerificationRequester{ActorType: domain.AuditActorUser, ActorID: user.ID})
	require.NoError(t, err)
	mails := env.mail.waitMails(t, notify.TemplateEmailVerification, 1)
	require.Equal(t, "gina@example.test", mails[0].to)
	link := mails[0].data.VerifyURL
	require.True(t, strings.HasPrefix(link, "https://sso.example.com/r/verify/auth/verify-email#token="), link)
	token := link[strings.Index(link, "#token=")+len("#token="):]

	// The page: no token in it (it stays in the fragment), strict CSP.
	resp, err := http.Get(env.ts.URL + "/r/verify/auth/verify-email")
	require.NoError(t, err)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(page), "Confirm your e-mail address")
	require.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'none'")

	// Another realm's page refuses it.
	other, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "elsewhere"})
	require.NoError(t, err)
	_ = other
	status, out, _ := env.post(t, "/r/elsewhere/auth/verify-email", map[string]string{"token": token})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_or_expired_token", out["error"])

	status, out, _ = env.post(t, "/r/verify/auth/verify-email", map[string]string{"token": token})
	require.Equal(t, http.StatusOK, status, "%v", out)
	got, err := env.users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, got.EmailVerifiedAt)

	status, out, _ = env.post(t, "/r/verify/auth/verify-email", map[string]string{"token": token})
	require.Equal(t, http.StatusBadRequest, status, "a link works once")
	require.Equal(t, "invalid_or_expired_token", out["error"])

	entries := auditOf(t, env, realm.ID, "user.email_verified")
	require.Len(t, entries, 1)
	require.Equal(t, domain.AuditActorUser, entries[0].ActorType)

	// The link was e-mailed and used: the e-mail is not sent twice.
	require.Len(t, env.mail.mails(notify.TemplateEmailVerification), 1)
}

// A link replaced before its e-mail could leave is not sent: the e-mail is
// cancelled (the user got the newer one).
func TestEmailOutbox_ReplacedLinkIsNotSent(t *testing.T) {
	env := setupResetEnv(t)
	ctx := context.Background()
	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "replaced"})
	require.NoError(t, err)
	hash, err := service.HashPassword("the old password")
	require.NoError(t, err)
	user, err := env.users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: "hugo", Email: "hugo@example.test", PasswordHash: hash, Status: domain.UserActive,
	})
	require.NoError(t, err)

	env.mail.setFail(errors.New("421 try again later"))
	for i := range 2 {
		status, _, _ := env.post(t, "/r/replaced/auth/forgot-password", map[string]string{"identifier": "hugo"})
		require.Equal(t, http.StatusAccepted, status)
		require.Eventually(t, func() bool {
			n, err := env.client.EmailOutbox.Query().
				Where(emailoutbox.UserID(user.ID), emailoutbox.AttemptsGT(0), emailoutbox.LockedUntilIsNil()).Count(ctx)
			return err == nil && n == i+1
		}, 10*time.Second, 20*time.Millisecond)
	}
	env.dispatcher.Close(ctx)
	env.mail.setFail(nil)
	restarted := env.newDispatcher(func() time.Time { return time.Now().Add(5 * time.Minute) })
	restarted.Start()
	t.Cleanup(func() { restarted.Close(context.Background()) })

	require.Eventually(t, func() bool {
		n, err := env.client.EmailOutbox.Query().Where(emailoutbox.UserID(user.ID), emailoutbox.StatusEQ(entschema.EmailOutboxPending)).Count(ctx)
		return err == nil && n == 0
	}, 10*time.Second, 20*time.Millisecond)
	rows, err := env.client.EmailOutbox.Query().Where(emailoutbox.UserID(user.ID)).All(ctx)
	require.NoError(t, err)
	statuses := map[entschema.EmailOutboxStatus]int{}
	for _, r := range rows {
		statuses[r.Status]++
	}
	require.Equal(t, map[entschema.EmailOutboxStatus]int{entschema.EmailOutboxSent: 1, entschema.EmailOutboxCancelled: 1}, statuses)
	require.Len(t, env.mail.mails(notify.TemplatePasswordReset), 1, "only the link that still works")
}

func auditOf(t *testing.T, env *resetEnv, realmID, action string) []*domain.AuditLog {
	t.Helper()
	logs, err := env.audit.ListByRealm(context.Background(), realmID)
	require.NoError(t, err)
	var out []*domain.AuditLog
	for _, l := range logs {
		if l.Action == action {
			out = append(out, l)
		}
	}
	return out
}
