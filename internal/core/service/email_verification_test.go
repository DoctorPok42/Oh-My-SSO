package service_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// memVerifications: the verification links, and MarkEmailVerified on the
// accounts of users (the same statement as the database: only if the
// address still is the one of the link).
type memVerifications struct {
	mu    sync.Mutex
	users *memUsers
	links map[string]*domain.EmailVerificationToken // by hash
	seq   int
}

func newMemVerifications(users *memUsers) *memVerifications {
	return &memVerifications{users: users, links: map[string]*domain.EmailVerificationToken{}}
}

func (m *memVerifications) Create(_ context.Context, t *domain.EmailVerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	c := *t
	c.ID = "evt-" + string(rune('0'+m.seq))
	m.links[t.TokenHash] = &c
	t.ID = c.ID
	return nil
}

func (m *memVerifications) GetByTokenHash(_ context.Context, hash string) (*domain.EmailVerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.links[hash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	c := *t
	return &c, nil
}

func (m *memVerifications) LatestCreatedAt(_ context.Context, userID string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last time.Time
	for _, t := range m.links {
		if t.UserID == userID && t.CreatedAt.After(last) {
			last = t.CreatedAt
		}
	}
	return last, nil
}

func (m *memVerifications) Consume(_ context.Context, id string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.links {
		if t.ID == id && t.UsedAt == nil {
			t.UsedAt = &at
			return true, nil
		}
	}
	return false, nil
}

func (m *memVerifications) DeleteUnusedByUser(_ context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for h, t := range m.links {
		if t.UserID == userID && t.UsedAt == nil {
			delete(m.links, h)
			n++
		}
	}
	return n, nil
}

func (m *memVerifications) MarkEmailVerified(_ context.Context, userID, email string, at time.Time) (bool, error) {
	m.users.mu.Lock()
	defer m.users.mu.Unlock()
	u, ok := m.users.byID[userID]
	if !ok || u.Email != email || u.EmailVerifiedAt != nil {
		return false, nil
	}
	u.EmailVerifiedAt = &at
	return true, nil
}

type verifyFixture struct {
	clock    *testClock
	user     *domain.User
	users    *memUsers
	links    *memVerifications
	notifier *recordingNotifier
	audit    *fakeAuditRepo
	svc      *service.EmailVerificationService
}

func newVerifyFixture() *verifyFixture {
	f := &verifyFixture{clock: newTestClock(), notifier: &recordingNotifier{}, audit: &fakeAuditRepo{}}
	f.user = &domain.User{ID: "u-erin", RealmID: "realm-a", Username: "erin", Email: "erin@example.test", Status: domain.UserActive}
	f.users = newMemUsers(f.user)
	f.links = newMemVerifications(f.users)
	f.svc = service.NewEmailVerificationService(service.EmailVerificationDeps{
		Tx: repository.NoTransaction{}, Users: f.users, Links: f.links, Notifier: f.notifier, Audit: f.audit, Now: f.clock.Now,
	})
	return f
}

var self = service.VerificationRequester{ActorType: domain.AuditActorUser, ActorID: "u-erin", IPAddress: "203.0.113.9"}

func (f *verifyFixture) send(t *testing.T) string {
	t.Helper()
	expires, err := f.svc.Send(context.Background(), f.user, self)
	require.NoError(t, err)
	require.Equal(t, f.clock.Now().Add(service.EmailVerificationTTL), expires)
	e := f.notifier.last()
	require.Equal(t, domain.NotificationEmailVerification, e.Kind)
	require.NotEmpty(t, e.ResetToken)
	return e.ResetToken
}

func TestEmailVerification_LinkVerifiesTheAddress(t *testing.T) {
	f := newVerifyFixture()
	ctx := context.Background()
	token := f.send(t)

	u, err := f.svc.Verify(ctx, "realm-a", token, "203.0.113.9", "test")
	require.NoError(t, err)
	require.NotNil(t, u.EmailVerifiedAt)
	require.Equal(t, f.clock.Now(), *u.EmailVerifiedAt)

	_, err = f.svc.Verify(ctx, "realm-a", token, "", "")
	require.ErrorIs(t, err, service.ErrEmailVerificationInvalid, "a link works once")

	var actions []string
	for _, e := range f.audit.entries {
		actions = append(actions, e.Action)
		require.Equal(t, "u-erin", e.TargetUserID)
	}
	require.Equal(t, []string{audit.UserEmailVerificationSent, audit.UserEmailVerified}, actions)

	_, err = f.svc.Send(ctx, f.users.byID["u-erin"], self)
	require.ErrorIs(t, err, service.ErrEmailAlreadyVerified)
}

// A link sent to an address the account no longer has proves nothing.
func TestEmailVerification_AddressChangedSince(t *testing.T) {
	f := newVerifyFixture()
	token := f.send(t)
	f.users.byID["u-erin"].Email = "erin@new.example"

	_, err := f.svc.Verify(context.Background(), "realm-a", token, "", "")
	require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	require.Nil(t, f.users.byID["u-erin"].EmailVerifiedAt)
}

func TestEmailVerification_RefusedLinks(t *testing.T) {
	ctx := context.Background()
	t.Run("another realm's page", func(t *testing.T) {
		f := newVerifyFixture()
		token := f.send(t)
		_, err := f.svc.Verify(ctx, "realm-b", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	})
	t.Run("expired", func(t *testing.T) {
		f := newVerifyFixture()
		token := f.send(t)
		f.clock.Advance(service.EmailVerificationTTL)
		_, err := f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	})
	t.Run("replaced by a newer one", func(t *testing.T) {
		f := newVerifyFixture()
		old := f.send(t)
		f.clock.Advance(2 * time.Minute)
		f.send(t)
		_, err := f.svc.Verify(ctx, "realm-a", old, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	})
	t.Run("unknown or empty", func(t *testing.T) {
		f := newVerifyFixture()
		for _, tok := range []string{"", "not-a-link"} {
			_, err := f.svc.Verify(ctx, "realm-a", tok, "", "")
			require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
		}
	})
	t.Run("suspended account", func(t *testing.T) {
		f := newVerifyFixture()
		token := f.send(t)
		f.users.byID["u-erin"].Status = domain.UserSuspended
		_, err := f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	})
}

// One e-mail a minute, whoever asks; none without a mail server.
func TestEmailVerification_SendLimits(t *testing.T) {
	f := newVerifyFixture()
	ctx := context.Background()
	f.send(t)
	_, err := f.svc.Send(ctx, f.user, self)
	require.ErrorIs(t, err, service.ErrEmailVerificationTooSoon)
	f.clock.Advance(time.Minute)
	f.send(t)

	off := service.NewEmailVerificationService(service.EmailVerificationDeps{
		Tx: repository.NoTransaction{}, Users: f.users, Links: f.links, Notifier: service.NopNotifier{},
	})
	require.False(t, off.Enabled())
	_, err = off.Send(ctx, f.user, self)
	require.ErrorIs(t, err, service.ErrEmailVerificationUnavailable)

	// An administrator writes their own entry (Silent).
	f.clock.Advance(time.Minute)
	before := len(f.audit.entries)
	_, err = f.svc.Send(ctx, f.user, service.VerificationRequester{ActorType: domain.AuditActorAdmin, ActorID: "root", Silent: true})
	require.NoError(t, err)
	require.Len(t, f.audit.entries, before)
}

// A reset or activation link that reached the account's address proves the
// user reads it (B-13); one handed over by an administrator does not.
func TestResetPassword_EmailedLinkVerifiesTheAddress(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		emailedTo string
		want      bool
	}{
		"e-mailed to the address":      {"carol@example.test", true},
		"handed over (not e-mailed)":   {"", false},
		"e-mailed to a former address": {"carol@old.example", false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newResetFixture(t)
			links := newMemVerifications(f.users)
			f.svc = service.NewPasswordResetService(service.PasswordResetDeps{
				Tx: repository.NoTransaction{}, Users: f.users, Tokens: f.tokens, Sessions: f.sessSvc,
				Lockout: f.lockout, Notifier: f.notifier, Audit: f.audit, Now: f.clock.Now, Verifications: links,
			})
			token := f.request(t, "carol")
			for _, tok := range f.tokens.byID {
				tok.EmailedTo = c.emailedTo // what the dispatcher records when the e-mail leaves
			}
			require.NoError(t, f.svc.ResetPassword(ctx, service.ResetPasswordInput{
				RealmID: resetRealm, Token: token, NewPassword: "a brand new passphrase",
			}))
			require.Equal(t, c.want, f.users.byID["u-carol"].EmailVerifiedAt != nil)
		})
	}
}
