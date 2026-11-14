package entstore_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/emailoutbox"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

type outboxFixture struct {
	ctx    context.Context
	client *ent.Client
	realm  *domain.Realm
	user   *domain.User
	outbox repository.EmailOutboxRepository
	now    time.Time
}

func newOutboxFixture(t *testing.T) *outboxFixture {
	t.Helper()
	ctx := context.Background()
	client := newTestClient(t)
	// The tests share the database: what other tests left waiting would be
	// claimed here.
	_, err := client.EmailOutbox.Update().Where(emailoutbox.StatusEQ(entschema.EmailOutboxPending)).
		SetStatus(entschema.EmailOutboxCancelled).Save(ctx)
	require.NoError(t, err)
	realm := newTestRealm(t, ctx, client)
	u, err := entstore.NewUserRepository(client).Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: "olga", Email: "olga@example.test", Status: domain.UserActive,
	})
	require.NoError(t, err)
	return &outboxFixture{
		ctx: ctx, client: client, realm: realm, user: u, outbox: entstore.NewEmailOutboxRepository(client),
		now: time.Now().UTC().Truncate(time.Millisecond),
	}
}

func (f *outboxFixture) add(t *testing.T, kind domain.NotificationKind, due time.Time) *domain.OutboxEmail {
	t.Helper()
	e := &domain.OutboxEmail{
		ID: uuid.NewString(), RealmID: f.realm.ID, UserID: f.user.ID, Kind: kind,
		Event: domain.NotificationEvent{
			Kind: kind, RealmID: f.realm.ID, UserID: f.user.ID, IPAddress: "203.0.113.7",
			ResetToken: "raw-link-token", ExpiresAt: f.now.Add(4 * time.Hour),
		},
		SealedToken:   "sealed-blob",
		NextAttemptAt: due, Deadline: f.now.Add(24 * time.Hour), CreatedAt: f.now,
	}
	require.NoError(t, f.outbox.Create(f.ctx, e))
	return e
}

// The event round-trips, but never with its raw link; the sealed one stays.
func TestEmailOutbox_CreateKeepsNoRawLink(t *testing.T) {
	f := newOutboxFixture(t)
	e := f.add(t, domain.NotificationAccountInvite, f.now)

	got, err := f.outbox.Get(f.ctx, e.ID)
	require.NoError(t, err)
	require.Equal(t, domain.OutboxPending, got.Status)
	require.Equal(t, "sealed-blob", got.SealedToken)
	require.Empty(t, got.Event.ResetToken)
	require.Equal(t, "203.0.113.7", got.Event.IPAddress)
	require.True(t, e.Event.ExpiresAt.Equal(got.Event.ExpiresAt))

	row, err := f.client.EmailOutbox.Get(f.ctx, e.ID)
	require.NoError(t, err)
	require.NotContains(t, row.Event, "raw-link-token")
}

func TestEmailOutbox_ClaimTakesDueRowsOnce(t *testing.T) {
	f := newOutboxFixture(t)
	later := f.add(t, domain.NotificationPasswordChanged, f.now.Add(time.Hour))
	first := f.add(t, domain.NotificationPasswordChanged, f.now.Add(-2*time.Minute))
	second := f.add(t, domain.NotificationPasswordChanged, f.now.Add(-time.Minute))

	got, err := f.outbox.Claim(f.ctx, "", f.now, time.Minute)
	require.NoError(t, err)
	require.Equal(t, first.ID, got.ID, "the most overdue first")
	require.Equal(t, 1, got.Attempts)

	got, err = f.outbox.Claim(f.ctx, "", f.now, time.Minute)
	require.NoError(t, err)
	require.Equal(t, second.ID, got.ID, "the held one is skipped")

	_, err = f.outbox.Claim(f.ctx, "", f.now, time.Minute)
	require.ErrorIs(t, err, repository.ErrNotFound, "the last one is not due")
	_, err = f.outbox.Claim(f.ctx, later.ID, f.now, time.Minute)
	require.ErrorIs(t, err, repository.ErrNotFound, "by id too: not due")

	// Its dispatcher died: after the lease, another one takes it over.
	got, err = f.outbox.Claim(f.ctx, "", f.now.Add(2*time.Minute), time.Minute)
	require.NoError(t, err)
	require.Equal(t, first.ID, got.ID)
	require.Equal(t, 2, got.Attempts)
}

// Many dispatchers at once (several servers): every e-mail is taken by
// exactly one of them.
func TestEmailOutbox_ConcurrentClaims(t *testing.T) {
	f := newOutboxFixture(t)
	want := map[string]bool{}
	for range 10 {
		want[f.add(t, domain.NotificationPasswordChanged, f.now.Add(-time.Second)).ID] = true
	}
	var mu sync.Mutex
	taken := map[string]int{}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				e, err := f.outbox.Claim(f.ctx, "", f.now, time.Hour)
				if errors.Is(err, repository.ErrNotFound) {
					return
				}
				if !assertNoErr(t, err) {
					return
				}
				mu.Lock()
				taken[e.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Len(t, taken, len(want))
	for id, n := range taken {
		require.True(t, want[id], id)
		require.Equal(t, 1, n, "claimed twice: %s", id)
	}
}

func assertNoErr(t *testing.T, err error) bool {
	if err != nil {
		t.Error(err)
		return false
	}
	return true
}

func TestEmailOutbox_Outcomes(t *testing.T) {
	f := newOutboxFixture(t)
	e := f.add(t, domain.NotificationAccountInvite, f.now)
	_, err := f.outbox.Claim(f.ctx, e.ID, f.now, time.Minute)
	require.NoError(t, err)

	// A failed attempt: due later, the error kept, no longer held.
	next := f.now.Add(30 * time.Second)
	require.NoError(t, f.outbox.Retry(f.ctx, e.ID, next, "dial tcp: connection refused", "olga@example.test", "account_invite"))
	got, _ := f.outbox.Get(f.ctx, e.ID)
	require.Equal(t, domain.OutboxPending, got.Status)
	require.True(t, next.Equal(got.NextAttemptAt))
	require.Equal(t, "dial tcp: connection refused", got.LastError)
	_, err = f.outbox.Claim(f.ctx, e.ID, next, time.Minute)
	require.NoError(t, err, "due again at its next attempt")

	require.NoError(t, f.outbox.Sent(f.ctx, e.ID, "olga@example.test", "account_invite", next))
	got, _ = f.outbox.Get(f.ctx, e.ID)
	require.Equal(t, domain.OutboxSent, got.Status)
	require.Empty(t, got.LastError)
	require.NotNil(t, got.SentAt)
	ok, err := f.outbox.Requeue(f.ctx, e.ID, f.now, f.now.Add(time.Hour))
	require.NoError(t, err)
	require.False(t, ok, "a sent e-mail is not sent again")

	// Failed, then sent again by an administrator: due now, attempts from 0.
	failed := f.add(t, domain.NotificationPasswordChanged, f.now)
	_, err = f.outbox.Claim(f.ctx, failed.ID, f.now, time.Minute)
	require.NoError(t, err)
	require.NoError(t, f.outbox.End(f.ctx, failed.ID, domain.OutboxFailed, "550 mailbox unavailable", "olga@example.test", "password_changed"))
	ok, err = f.outbox.Requeue(f.ctx, failed.ID, f.now.Add(time.Hour), f.now.Add(25*time.Hour))
	require.NoError(t, err)
	require.True(t, ok)
	got, _ = f.outbox.Get(f.ctx, failed.ID)
	require.Equal(t, domain.OutboxPending, got.Status)
	require.Zero(t, got.Attempts)
	require.True(t, f.now.Add(25*time.Hour).Equal(got.Deadline))

	// One being sent right now is left to its dispatcher.
	_, err = f.outbox.Claim(f.ctx, failed.ID, f.now.Add(time.Hour), time.Minute)
	require.NoError(t, err)
	ok, err = f.outbox.Requeue(f.ctx, failed.ID, f.now.Add(time.Hour), f.now.Add(25*time.Hour))
	require.NoError(t, err)
	require.False(t, ok)

	// Long errors are cut.
	long := f.add(t, domain.NotificationPasswordChanged, f.now)
	require.NoError(t, f.outbox.End(f.ctx, long.ID, domain.OutboxCancelled, strings.Repeat("é", 2000)+"\x00", "", ""))
	got, _ = f.outbox.Get(f.ctx, long.ID)
	require.LessOrEqual(t, len(got.LastError), 510)
}

func TestEmailOutbox_Lists(t *testing.T) {
	f := newOutboxFixture(t)
	db, err := sql.Open("pgx", testDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var ids []string
	for i := range 3 {
		e := f.add(t, domain.NotificationAccountInvite, f.now)
		// created_at one second apart: the newest first.
		_, err := db.ExecContext(f.ctx, "UPDATE email_outbox SET created_at = $1 WHERE id = $2", f.now.Add(time.Duration(i)*time.Second), e.ID)
		require.NoError(t, err)
		ids = append(ids, e.ID)
	}
	list, err := f.outbox.ListByUser(f.ctx, f.user.ID, 2)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, ids[2], list[0].ID)
	require.Equal(t, ids[1], list[1].ID)

	latest, err := f.outbox.LatestByUsers(f.ctx, []string{f.user.ID, "nobody"}, domain.NotificationAccountInvite, f.now)
	require.NoError(t, err)
	require.Len(t, latest, 1)
	require.Equal(t, ids[2], latest[f.user.ID].ID)
	latest, err = f.outbox.LatestByUsers(f.ctx, []string{f.user.ID}, domain.NotificationAccountInvite, f.now.Add(time.Hour))
	require.NoError(t, err)
	require.Empty(t, latest, "asked for before the import")
}

// The purge removes the e-mails that ended, never the waiting ones; deleting
// the account takes its e-mails along.
func TestEmailOutbox_PurgeAndCascade(t *testing.T) {
	f := newOutboxFixture(t)
	sent := f.add(t, domain.NotificationPasswordChanged, f.now)
	require.NoError(t, f.outbox.Sent(f.ctx, sent.ID, "olga@example.test", "password_changed", f.now))
	pending := f.add(t, domain.NotificationPasswordChanged, f.now)

	purge := entstore.NewPurgeRepository(f.client)
	n, err := purge.DeleteEndedEmails(f.ctx, f.realm.ID, time.Now().Add(time.Hour), 100)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = f.outbox.Get(f.ctx, sent.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
	_, err = f.outbox.Get(f.ctx, pending.ID)
	require.NoError(t, err)

	require.NoError(t, entstore.NewUserRepository(f.client).Delete(f.ctx, f.user.ID))
	_, err = f.outbox.Get(f.ctx, pending.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
}

// B-13: the verified state of an address, in its column.
func TestUser_EmailVerifiedState(t *testing.T) {
	f := newOutboxFixture(t)
	users := entstore.NewUserRepository(f.client)
	links := entstore.NewEmailVerificationRepository(f.client)
	yes, no := true, false

	u, err := users.Update(f.ctx, f.user.ID, repository.UpdateUserParams{EmailVerified: &yes})
	require.NoError(t, err)
	require.NotNil(t, u.EmailVerifiedAt)
	since := *u.EmailVerifiedAt
	u, err = users.Update(f.ctx, f.user.ID, repository.UpdateUserParams{EmailVerified: &yes})
	require.NoError(t, err)
	require.True(t, since.Equal(*u.EmailVerifiedAt), "already verified: the date stays")

	// A new address is not verified.
	other := "olga@new.example"
	u, err = users.Update(f.ctx, f.user.ID, repository.UpdateUserParams{Email: &other})
	require.NoError(t, err)
	require.Nil(t, u.EmailVerifiedAt)

	// Unless the administrator says it is, from now.
	third := "olga@third.example"
	u, err = users.Update(f.ctx, f.user.ID, repository.UpdateUserParams{Email: &third, EmailVerified: &yes})
	require.NoError(t, err)
	require.NotNil(t, u.EmailVerifiedAt)
	u, err = users.Update(f.ctx, f.user.ID, repository.UpdateUserParams{EmailVerified: &no})
	require.NoError(t, err)
	require.Nil(t, u.EmailVerifiedAt)

	// MarkEmailVerified: only for the address of the link.
	ok, err := links.MarkEmailVerified(f.ctx, f.user.ID, "olga@new.example", f.now)
	require.NoError(t, err)
	require.False(t, ok, "the account no longer has that address")
	ok, err = links.MarkEmailVerified(f.ctx, f.user.ID, "OLGA@third.example", f.now)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = links.MarkEmailVerified(f.ctx, f.user.ID, third, f.now.Add(time.Hour))
	require.NoError(t, err)
	require.False(t, ok, "already verified")
	u, err = users.GetByID(f.ctx, f.user.ID)
	require.NoError(t, err)
	require.True(t, f.now.Equal(*u.EmailVerifiedAt))
}

func TestEmailVerificationLinks(t *testing.T) {
	f := newOutboxFixture(t)
	links := entstore.NewEmailVerificationRepository(f.client)
	last, err := links.LatestCreatedAt(f.ctx, f.user.ID)
	require.NoError(t, err)
	require.True(t, last.IsZero())

	tok := &domain.EmailVerificationToken{UserID: f.user.ID, Email: "Olga@Example.test", TokenHash: "h1", ExpiresAt: f.now.Add(time.Hour), CreatedAt: f.now}
	require.NoError(t, links.Create(f.ctx, tok))
	require.NotEmpty(t, tok.ID)
	got, err := links.GetByTokenHash(f.ctx, "h1")
	require.NoError(t, err)
	require.Equal(t, "olga@example.test", got.Email, "stored normalized, like the account's")
	last, err = links.LatestCreatedAt(f.ctx, f.user.ID)
	require.NoError(t, err)
	require.True(t, f.now.Equal(last))

	ok, err := links.Consume(f.ctx, tok.ID, f.now)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = links.Consume(f.ctx, tok.ID, f.now)
	require.NoError(t, err)
	require.False(t, ok, "once")

	require.NoError(t, links.Create(f.ctx, &domain.EmailVerificationToken{UserID: f.user.ID, Email: "olga@example.test", TokenHash: "h2", ExpiresAt: f.now.Add(time.Hour)}))
	n, err := links.DeleteUnusedByUser(f.ctx, f.user.ID)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the used one stays (purged later)")

	purge := entstore.NewPurgeRepository(f.client)
	n, err = purge.DeleteEndedVerificationLinks(f.ctx, f.realm.ID, f.now.Add(time.Second), 100)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

// The dispatcher records where a reset or activation link went.
func TestResetLink_MarkEmailed(t *testing.T) {
	f := newOutboxFixture(t)
	tokens := entstore.NewPasswordResetTokenRepository(f.client)
	_, err := tokens.Create(f.ctx, repository.CreatePasswordResetTokenParams{UserID: f.user.ID, TokenHash: "rh", ExpiresAt: f.now.Add(time.Hour)})
	require.NoError(t, err)
	require.NoError(t, tokens.MarkEmailed(f.ctx, "rh", "Olga@Example.test"))
	got, err := tokens.GetByTokenHash(f.ctx, "rh")
	require.NoError(t, err)
	require.Equal(t, "olga@example.test", got.EmailedTo)
	require.NoError(t, tokens.MarkEmailed(f.ctx, "gone", "x@example.test"), "a link replaced meanwhile: nothing to do")
}
