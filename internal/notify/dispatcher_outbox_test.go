package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// --- fakes -------------------------------------------------------------------

// memOutbox is the outbox in memory, with the semantics of the database one
// (Claim: pending, due, not held; attempts + 1).
type memOutbox struct {
	mu   sync.Mutex
	rows map[string]*domain.OutboxEmail
	held map[string]time.Time // id → locked until
	fail error                // every call fails with it
}

func newMemOutbox() *memOutbox {
	return &memOutbox{rows: map[string]*domain.OutboxEmail{}, held: map[string]time.Time{}}
}

func (m *memOutbox) Create(_ context.Context, e *domain.OutboxEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	c := *e
	if c.Status == "" {
		c.Status = domain.OutboxPending
	}
	m.rows[e.ID] = &c
	return nil
}

func (m *memOutbox) Claim(_ context.Context, id string, now time.Time, lease time.Duration) (*domain.OutboxEmail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	var best *domain.OutboxEmail
	for _, r := range m.rows {
		if r.Status != domain.OutboxPending || r.NextAttemptAt.After(now) || (id != "" && r.ID != id) {
			continue
		}
		if until, ok := m.held[r.ID]; ok && !until.Before(now) {
			continue
		}
		if best == nil || r.NextAttemptAt.Before(best.NextAttemptAt) {
			best = r
		}
	}
	if best == nil {
		return nil, repository.ErrNotFound
	}
	best.Attempts++
	m.held[best.ID] = now.Add(lease)
	c := *best
	return &c, nil
}

func (m *memOutbox) end(id string, f func(r *domain.OutboxEmail)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	delete(m.held, id)
	f(m.rows[id])
	return nil
}

func (m *memOutbox) Sent(_ context.Context, id, recipient, template string, at time.Time) error {
	return m.end(id, func(r *domain.OutboxEmail) {
		r.Status, r.Recipient, r.Template, r.SentAt, r.LastError = domain.OutboxSent, recipient, template, &at, ""
	})
}

func (m *memOutbox) Retry(_ context.Context, id string, next time.Time, lastError, recipient, template string) error {
	return m.end(id, func(r *domain.OutboxEmail) {
		r.NextAttemptAt, r.LastError = next, lastError
		if recipient != "" {
			r.Recipient, r.Template = recipient, template
		}
	})
}

func (m *memOutbox) End(_ context.Context, id string, status domain.OutboxStatus, reason, recipient, template string) error {
	return m.end(id, func(r *domain.OutboxEmail) {
		r.Status, r.LastError = status, reason
		if recipient != "" {
			r.Recipient, r.Template = recipient, template
		}
	})
}

func (m *memOutbox) Requeue(_ context.Context, id string, now, deadline time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[id]
	if r == nil || (r.Status != domain.OutboxFailed && r.Status != domain.OutboxPending) {
		return false, nil
	}
	r.Status, r.Attempts, r.NextAttemptAt, r.Deadline = domain.OutboxPending, 0, now, deadline
	return true, nil
}

func (m *memOutbox) Get(_ context.Context, id string) (*domain.OutboxEmail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *memOutbox) ListByUser(context.Context, string, int) ([]*domain.OutboxEmail, error) {
	return nil, errors.New("not used")
}

func (m *memOutbox) LatestByUsers(context.Context, []string, domain.NotificationKind, time.Time) (map[string]*domain.OutboxEmail, error) {
	return nil, errors.New("not used")
}

func (m *memOutbox) only(t *testing.T) *domain.OutboxEmail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	require.Len(t, m.rows, 1)
	for _, r := range m.rows {
		c := *r
		return &c
	}
	return nil
}

// fakeSealer "encrypts" by tagging with the aad: a value moved to another
// row does not open, like the envelope.
type fakeSealer struct{}

func (fakeSealer) Seal(_ context.Context, _ string, plaintext, aad []byte) (string, error) {
	return fmt.Sprintf("sealed(%s)%x", aad, plaintext), nil
}

func (fakeSealer) Open(_ context.Context, sealed string, aad []byte) ([]byte, error) {
	prefix := fmt.Sprintf("sealed(%s)", aad)
	if !strings.HasPrefix(sealed, prefix) {
		return nil, errors.New("authentication failed")
	}
	var out []byte
	_, err := fmt.Sscanf(strings.TrimPrefix(sealed, prefix), "%x", &out)
	return out, err
}

type fakeLinks struct {
	usable  bool
	err     error
	emailed []string // "<token> → <address>"
}

func (l *fakeLinks) Usable(context.Context, domain.NotificationKind, string) (bool, error) {
	return l.usable, l.err
}

func (l *fakeLinks) Emailed(_ context.Context, _ domain.NotificationKind, token, address string) error {
	l.emailed = append(l.emailed, token+" → "+address)
	return nil
}

// scriptedSender answers with errs in turn, then nil.
type scriptedSender struct {
	mu   sync.Mutex
	errs []error
	sent []Data
	to   []string
}

func (s *scriptedSender) Send(_ context.Context, to string, _ Template, data Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		return err
	}
	s.sent, s.to = append(s.sent, data), append(s.to, to)
	return nil
}

func (s *scriptedSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

type usersStub struct {
	repository.UserRepository
	users map[string]*domain.User
}

func (u usersStub) GetByID(_ context.Context, id string) (*domain.User, error) {
	if x, ok := u.users[id]; ok {
		return x, nil
	}
	return nil, repository.ErrNotFound
}

type realmsStub struct{ repository.RealmRepository }

func (realmsStub) GetByID(_ context.Context, id string) (*domain.Realm, error) {
	return &domain.Realm{ID: id, Name: "acme", DisplayName: "Acme"}, nil
}

type recordingAudit struct {
	repository.AuditLogRepository
	mu      sync.Mutex
	entries []repository.CreateAuditLogParams
}

func (a *recordingAudit) Create(_ context.Context, p repository.CreateAuditLogParams) (*domain.AuditLog, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, p)
	return &domain.AuditLog{}, nil
}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

type outboxEnv struct {
	d      *Dispatcher
	outbox *memOutbox
	sender *scriptedSender
	links  *fakeLinks
	audit  *recordingAudit
	clock  *clock
}

func newOutboxEnv(cfg DispatcherConfig, sendErrs ...error) *outboxEnv {
	env := &outboxEnv{
		outbox: newMemOutbox(), sender: &scriptedSender{errs: sendErrs}, links: &fakeLinks{usable: true},
		audit: &recordingAudit{}, clock: &clock{t: time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)},
	}
	cfg.PublicURL = "https://sso.example.com"
	env.d = NewDispatcher(cfg, DispatcherDeps{
		Sender: env.sender, Audit: env.audit, Outbox: env.outbox, Sealer: fakeSealer{}, Links: env.links,
		Users: usersStub{users: map[string]*domain.User{
			"u1": {ID: "u1", Username: "dana", Email: "dana@example.test"},
			"u2": {ID: "u2", Username: "noaddress"},
		}},
		Realms: realmsStub{}, Now: env.clock.Now,
	})
	return env
}

func invite(token string, expires time.Time) domain.NotificationEvent {
	return domain.NotificationEvent{
		Kind: domain.NotificationAccountInvite, RealmID: "r1", UserID: "u1",
		OccurredAt: expires.Add(-4 * time.Hour), ResetToken: token, ExpiresAt: expires,
	}
}

// --- tests -------------------------------------------------------------------

// The link is the one secret of an e-mail: never in clear in the outbox,
// and bound to its row.
func TestEnqueueSealsTheLink(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{})
	ctx := context.Background()
	expires := env.clock.t.Add(4 * time.Hour)
	id, err := env.d.Enqueue(ctx, invite("s3cret-token", expires))
	require.NoError(t, err)

	row := env.outbox.only(t)
	require.Equal(t, id, row.ID)
	require.Empty(t, row.Event.ResetToken)
	require.NotEmpty(t, row.SealedToken)
	require.NotContains(t, row.SealedToken, "s3cret-token")
	require.Equal(t, domain.OutboxPending, row.Status)
	require.Equal(t, env.clock.t, row.NextAttemptAt, "due at once")
	require.Equal(t, expires, row.Deadline, "an activation link that expires in 4 h is not worth sending after")

	require.NoError(t, env.d.DeliverNow(ctx, id))
	require.Equal(t, 1, env.sender.count())
	require.Contains(t, env.sender.sent[0].ResetURL, "s3cret-token")
	row = env.outbox.only(t)
	require.Equal(t, domain.OutboxSent, row.Status)
	require.Equal(t, "dana@example.test", row.Recipient)
	require.Equal(t, []string{"s3cret-token → dana@example.test"}, env.links.emailed, "the link is known to have reached the address")

	// Copied onto another row, the sealed link does not open.
	other := *row
	other.ID, other.Status, other.Attempts = "other", domain.OutboxPending, 0
	require.NoError(t, env.outbox.Create(ctx, &other))
	err = env.d.DeliverNow(ctx, "other")
	require.ErrorIs(t, err, ErrPermanent)
	got, _ := env.outbox.Get(ctx, "other")
	require.Equal(t, domain.OutboxFailed, got.Status)
	require.Contains(t, got.LastError, "decrypt")
}

// An alert without a link has 24 h; an e-mail with a link without sealer
// is refused rather than stored in clear.
func TestEnqueueDeadlineAndSealer(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{})
	ctx := context.Background()
	_, err := env.d.Enqueue(ctx, domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u1"})
	require.NoError(t, err)
	require.Equal(t, env.clock.t.Add(24*time.Hour), env.outbox.only(t).Deadline)

	plain := NewDispatcher(DispatcherConfig{}, DispatcherDeps{Outbox: newMemOutbox()})
	_, err = plain.Enqueue(ctx, invite("tok", env.clock.t.Add(time.Hour)))
	require.Error(t, err)
}

// A security alert the realm does not send leaves no row.
func TestEnqueueSkipsUnwantedAlerts(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{})
	id, err := env.d.Enqueue(context.Background(), domain.NotificationEvent{Kind: domain.NotificationNewDeviceLogin, RealmID: "r1", UserID: "u1"})
	require.NoError(t, err)
	require.Empty(t, id)
	require.Empty(t, env.outbox.rows)
}

// A mail server outage: the e-mail waits and goes when the server is back,
// with one audit entry, at the end.
func TestFailedAttemptIsRetriedLater(t *testing.T) {
	smtpDown := errors.New("dial tcp: connection refused")
	env := newOutboxEnv(DispatcherConfig{}, smtpDown, smtpDown)
	ctx := context.Background()
	id, err := env.d.Enqueue(ctx, domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u1"})
	require.NoError(t, err)

	require.ErrorIs(t, env.d.DeliverNow(ctx, id), smtpDown)
	row := env.outbox.only(t)
	require.Equal(t, domain.OutboxPending, row.Status)
	require.Equal(t, 1, row.Attempts)
	require.Equal(t, env.clock.t.Add(30*time.Second), row.NextAttemptAt)
	require.Contains(t, row.LastError, "connection refused")
	require.Empty(t, env.audit.entries, "not over yet: logged, not audited")

	require.NoError(t, env.d.DeliverNow(ctx, id), "not due yet: left alone")
	require.Equal(t, 1, env.outbox.only(t).Attempts)

	env.clock.t = env.clock.t.Add(30 * time.Second)
	require.ErrorIs(t, env.d.DeliverNow(ctx, id), smtpDown)
	require.Equal(t, env.clock.t.Add(time.Minute), env.outbox.only(t).NextAttemptAt, "the delay doubles")

	env.clock.t = env.clock.t.Add(time.Minute)
	require.NoError(t, env.d.DeliverNow(ctx, id))
	row = env.outbox.only(t)
	require.Equal(t, domain.OutboxSent, row.Status)
	require.Empty(t, row.LastError)
	require.Len(t, env.audit.entries, 1)
	require.Equal(t, "sent", env.audit.entries[0].Details["status"])
	require.Equal(t, 3, env.audit.entries[0].Details["attempts"])
}

func TestRetryDelayDoublesUpToTheCap(t *testing.T) {
	d := NewDispatcher(DispatcherConfig{}, DispatcherDeps{})
	var got []time.Duration
	for n := 1; n <= 11; n++ {
		got = append(got, d.retryDelay(n))
	}
	require.Equal(t, []time.Duration{
		30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, 64 * time.Minute, 2 * time.Hour, 2 * time.Hour, 2 * time.Hour,
	}, got)
	// Attempts within 24 h: enough to ride out a long outage, without
	// hammering the mail server.
	var total time.Duration
	attempts := 1
	for ; total+d.retryDelay(attempts) <= 24*time.Hour; attempts++ {
		total += d.retryDelay(attempts)
	}
	require.Equal(t, 19, attempts, "the first attempt and 18 more")
}

// Out of time: failed, audited, logged.
func TestGivesUpAtTheDeadline(t *testing.T) {
	smtpDown := errors.New("connection refused")
	env := newOutboxEnv(DispatcherConfig{}, smtpDown)
	ctx := context.Background()
	id, err := env.d.Enqueue(ctx, invite("tok", env.clock.t.Add(20*time.Second)))
	require.NoError(t, err)

	require.ErrorIs(t, env.d.DeliverNow(ctx, id), smtpDown)
	row := env.outbox.only(t)
	require.Equal(t, domain.OutboxFailed, row.Status, "the next attempt would come after the link expired")
	require.Contains(t, row.LastError, "gave up after 1 attempts")
	require.Equal(t, "dana@example.test", row.Recipient)
	require.Len(t, env.audit.entries, 1)
	require.Equal(t, "failed", env.audit.entries[0].Details["status"])
	require.Equal(t, domain.AuditLogFailure, env.audit.entries[0].Status)
}

// A refusal of the mail server (bad address...) is final at once.
func TestPermanentFailureIsFinal(t *testing.T) {
	refused := errors.Join(ErrPermanent, errors.New("550 no such user"))
	env := newOutboxEnv(DispatcherConfig{}, refused)
	ctx := context.Background()
	id, err := env.d.Enqueue(ctx, domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u1"})
	require.NoError(t, err)
	require.ErrorIs(t, env.d.DeliverNow(ctx, id), ErrPermanent)
	row := env.outbox.only(t)
	require.Equal(t, domain.OutboxFailed, row.Status)
	require.Contains(t, row.LastError, "550 no such user")
	require.NotContains(t, row.LastError, "gave up")
	require.Len(t, env.audit.entries, 1)
}

// An e-mail that is no longer worth sending is cancelled, not sent, and not
// audited as a failure.
func TestCancelledEmails(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		event  domain.NotificationEvent
		usable bool
		reason string
	}{
		"its link was used or replaced": {invite("tok", time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)), false, "link"},
		"the account is gone":           {domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "gone"}, true, "no longer exists"},
		"the account has no address":    {domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u2"}, true, "no e-mail address"},
	} {
		t.Run(name, func(t *testing.T) {
			env := newOutboxEnv(DispatcherConfig{})
			env.links.usable = c.usable
			id, err := env.d.Enqueue(ctx, c.event)
			require.NoError(t, err)
			require.NoError(t, env.d.DeliverNow(ctx, id))
			row := env.outbox.only(t)
			require.Equal(t, domain.OutboxCancelled, row.Status)
			require.Contains(t, row.LastError, c.reason)
			require.Zero(t, env.sender.count())
			require.Empty(t, env.audit.entries)
		})
	}
}

// The workers send what a previous run left, and retry on their own. Close
// leaves the rest in the outbox and refuses new e-mails.
func TestWorkersSendWhatIsDue(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{PollInterval: 10 * time.Millisecond, Workers: 2})
	ctx := context.Background()
	// Left by a previous run (written before Start).
	for i := range 5 {
		require.NoError(t, env.outbox.Create(ctx, &domain.OutboxEmail{
			ID: fmt.Sprintf("old-%d", i), RealmID: "r1", UserID: "u1", Kind: domain.NotificationPasswordChanged,
			Event:         domain.NotificationEvent{Kind: domain.NotificationPasswordChanged},
			NextAttemptAt: env.clock.t.Add(-time.Hour), Deadline: env.clock.t.Add(time.Hour),
		}))
	}
	env.d.Start()
	_, err := env.d.Enqueue(ctx, domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u1"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return env.sender.count() == 6 }, 5*time.Second, 5*time.Millisecond)

	env.d.Close(ctx)
	require.ErrorIs(t, env.d.NotifyWait(ctx, domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u1"}), ErrDispatcherClosed)
	for _, r := range env.outbox.rows {
		require.Equal(t, domain.OutboxSent, r.Status, r.ID)
		require.Equal(t, 1, r.Attempts, "each sent once")
	}
}

// A server stopping in the middle of an attempt leaves the e-mail due at
// once for the next start, without giving up on it.
func TestStoppingServerKeepsTheEmail(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	id, err := env.d.Enqueue(ctx, invite("tok", env.clock.t.Add(10*time.Second)))
	require.NoError(t, err)
	env.sender.errs = []error{context.Canceled}
	cancel()
	require.Error(t, env.d.DeliverNow(ctx, id))
	row := env.outbox.only(t)
	require.Equal(t, domain.OutboxPending, row.Status, "not the mail server's fault")
	require.Equal(t, env.clock.t, row.NextAttemptAt)
}

// Notify when the database is down: the e-mail is lost, but said so.
func TestNotifyWithoutOutboxIsAudited(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{})
	env.outbox.fail = errors.New("database down")
	env.d.Notify(context.Background(), domain.NotificationEvent{Kind: domain.NotificationPasswordChanged, RealmID: "r1", UserID: "u1"})
	require.Len(t, env.audit.entries, 1)
	require.Equal(t, "failed", env.audit.entries[0].Details["status"])
	require.Contains(t, env.audit.entries[0].Details["error"], "not queued")
}

// A batch stays out of the audit log, except for what went wrong.
func TestQuietAuditOnlyKeepsFailures(t *testing.T) {
	for name, c := range map[string]struct {
		quiet bool
		err   error
		want  int
	}{
		"an e-mail":             {false, nil, 1},
		"an e-mail that failed": {false, errors.New("smtp"), 1},
		"one of a batch":        {true, nil, 0},
		"one that failed":       {true, errors.New("smtp"), 1},
	} {
		a := &recordingAudit{}
		d := NewDispatcher(DispatcherConfig{}, DispatcherDeps{Audit: a})
		d.writeAudit(context.Background(), domain.NotificationEvent{QuietAudit: c.quiet}, "a@b.example", TemplateAccountInvite, 1, c.err)
		if len(a.entries) != c.want {
			t.Errorf("%s: %d entries, want %d", name, len(a.entries), c.want)
		}
	}
}

// A bulk action's e-mails are recorded in its one entry when queued.
func TestEnqueueInBatch(t *testing.T) {
	env := newOutboxEnv(DispatcherConfig{})
	b := audit.NewBatch("op-1")
	b.Item("u1")
	_, err := env.d.Enqueue(audit.WithBatch(context.Background(), b), invite("tok", env.clock.t.Add(time.Hour)))
	require.NoError(t, err)
	row := env.outbox.only(t)
	require.True(t, row.Event.QuietAudit)
	require.Equal(t, "op-1", row.Event.OperationID)
	require.True(t, slices.ContainsFunc(b.Close()["u1"], func(e audit.Entry) bool { return e.Action == audit.NotificationSent }))
}
