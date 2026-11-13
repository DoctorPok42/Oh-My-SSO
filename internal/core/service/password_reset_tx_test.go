package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// markingTx is a Transactor whose transactions mark their context, so that
// the fakes can tell what is written inside one. The real rollback is
// checked against PostgreSQL (entstore's tx_integration_test.go).
type markingTx struct {
	mu    sync.Mutex
	calls int
}

type inTxKey struct{}

func (m *markingTx) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return fn(context.WithValue(ctx, inTxKey{}, true))
}

func inTx(ctx context.Context) bool { v, _ := ctx.Value(inTxKey{}).(bool); return v }

// txLog records, for each write of interest, whether it ran in a transaction.
type txLog struct {
	mu     sync.Mutex
	writes map[string]bool
}

func (l *txLog) note(ctx context.Context, what string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writes == nil {
		l.writes = map[string]bool{}
	}
	l.writes[what] = inTx(ctx)
}

func (l *txLog) get(t *testing.T, what string) bool {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	in, ok := l.writes[what]
	require.True(t, ok, "%s was not written", what)
	return in
}

type loggedUsers struct {
	*memUsers
	log *txLog
}

func (u loggedUsers) Update(ctx context.Context, id string, p repository.UpdateUserParams) (*domain.User, error) {
	if p.PasswordHash != nil {
		u.log.note(ctx, "password")
	}
	return u.memUsers.Update(ctx, id, p)
}

type loggedResetTokens struct {
	*memResetTokens
	log *txLog
}

func (r loggedResetTokens) ConsumeIfUnused(ctx context.Context, id string, at time.Time) (bool, error) {
	r.log.note(ctx, "link")
	return r.memResetTokens.ConsumeIfUnused(ctx, id, at)
}

type loggedSessions struct {
	*fakeSessionRepo
	log *txLog
}

func (s loggedSessions) RevokeAllByUser(ctx context.Context, userID string, reason domain.SessionRevokedReason) ([]*domain.Session, error) {
	s.log.note(ctx, "sessions")
	return s.fakeSessionRepo.RevokeAllByUser(ctx, userID, reason)
}

type loggedAudit struct {
	*fakeAuditRepo
	log *txLog
}

func (a loggedAudit) Create(ctx context.Context, p repository.CreateAuditLogParams) (*domain.AuditLog, error) {
	a.log.note(ctx, "audit")
	return a.fakeAuditRepo.Create(ctx, p)
}

type loggedNotifier struct {
	*recordingNotifier
	log *txLog
}

func (n loggedNotifier) Notify(ctx context.Context, e domain.NotificationEvent) {
	if e.Kind == domain.NotificationPasswordChanged {
		n.log.note(ctx, "e-mail")
	}
	n.recordingNotifier.Notify(ctx, e)
}

type loggedCache struct {
	fakeSessionCache
	log *txLog
}

func (c loggedCache) MarkRevoked(ctx context.Context, tokenHash string, ttl time.Duration) error {
	c.log.note(ctx, "cache")
	return c.fakeSessionCache.MarkRevoked(ctx, tokenHash, ttl)
}

// revocationObserver records the "every session revoked" notices (the
// trusted devices listen to them).
type revocationObserver struct {
	mu      sync.Mutex
	log     *txLog
	reasons []domain.SessionRevokedReason
}

func (o *revocationObserver) AllSessionsRevoked(ctx context.Context, _ string, reason domain.SessionRevokedReason) {
	if o.log != nil {
		o.log.note(ctx, "observers")
	}
	o.mu.Lock()
	o.reasons = append(o.reasons, reason)
	o.mu.Unlock()
}

func (o *revocationObserver) calls() []domain.SessionRevokedReason {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]domain.SessionRevokedReason(nil), o.reasons...)
}

// brokenSessionCache: Valkey does not answer the tombstones.
type brokenSessionCache struct{ fakeSessionCache }

func (brokenSessionCache) MarkRevoked(context.Context, string, time.Duration) error {
	return errors.New("valkey: connection refused")
}

// B-06: the link, the password and the sessions in one transaction; the
// audit entry and the e-mail after it.
func TestPasswordReset_WritesInOneTransaction(t *testing.T) {
	f := newResetFixture(t)
	ctx := context.Background()
	_, sess, err := f.sessSvc.Create(ctx, service.CreateSessionInput{RealmID: resetRealm, UserID: f.user.ID})
	require.NoError(t, err)

	log := &txLog{}
	tx := &markingTx{}
	observer := &revocationObserver{log: log}
	sessions := service.NewSessionService(loggedSessions{f.sessions, log}, fakeSettingsRepo{},
		&fakeTokenRepo{byJTI: map[string]*domain.Token{}}, loggedCache{log: log}, service.WithClock(f.clock.Now),
		service.WithRevocationObserver(observer))
	svc := service.NewPasswordResetService(service.PasswordResetDeps{
		Tx: tx, Users: loggedUsers{f.users, log}, Tokens: loggedResetTokens{f.tokens, log}, Sessions: sessions,
		Notifier: loggedNotifier{f.notifier, log}, Audit: loggedAudit{f.audit, log}, Now: f.clock.Now,
	})
	f.svc = svc
	token := f.request(t, "carol")
	require.NoError(t, f.reset(token, newPassword))

	require.Equal(t, 1, tx.calls)
	for _, w := range []string{"link", "password", "sessions"} {
		require.True(t, log.get(t, w), "%s: in the transaction", w)
	}
	for _, w := range []string{"cache", "observers", "audit", "e-mail"} {
		require.False(t, log.get(t, w), "%s: after the commit", w)
	}
	require.Equal(t, domain.SessionRevoked, f.sessions.byID[sess.ID].Status)
	require.Equal(t, []domain.SessionRevokedReason{domain.SessionRevokedPasswordReset}, observer.calls(),
		"the trusted devices are told once")
}

// A session cache that does not answer once the password has changed does
// not turn the reset into an error: the change is done, audited and
// e-mailed (before, the user got a 500 and no "password changed" e-mail).
func TestPasswordReset_CacheFailureAfterTheChangeIsNotAnError(t *testing.T) {
	f := newResetFixture(t)
	ctx := context.Background()
	f.sessSvc = service.NewSessionService(f.sessions, fakeSettingsRepo{}, &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
		brokenSessionCache{}, service.WithClock(f.clock.Now))
	f.svc = service.NewPasswordResetService(service.PasswordResetDeps{
		Tx: &markingTx{}, Users: f.users, Tokens: f.tokens, Sessions: f.sessSvc, Lockout: f.lockout,
		Notifier: f.notifier, Audit: f.audit, Now: f.clock.Now,
	})
	_, sess, err := f.sessSvc.Create(ctx, service.CreateSessionInput{RealmID: resetRealm, UserID: f.user.ID})
	require.NoError(t, err)

	token := f.request(t, "carol")
	require.NoError(t, f.reset(token, newPassword))

	require.NoError(t, f.login(newPassword))
	require.Equal(t, domain.SessionRevoked, f.sessions.byID[sess.ID].Status, "revoked in the database")
	require.Contains(t, f.audit.actions(), "user.password_reset")
	require.Equal(t, domain.NotificationPasswordChanged, f.notifier.last().Kind)
}

// A failure inside the transaction is the answer, and nothing after it
// (audit, e-mail) happens.
func TestPasswordReset_FailureInTheTransactionStopsThere(t *testing.T) {
	f := newResetFixture(t)
	boom := errors.New("database down")
	observer := &revocationObserver{}
	sessions := service.NewSessionService(f.sessions, fakeSettingsRepo{}, &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
		fakeSessionCache{}, service.WithClock(f.clock.Now), service.WithRevocationObserver(observer))
	f.svc = service.NewPasswordResetService(service.PasswordResetDeps{
		Tx: &markingTx{}, Users: failingPasswordUsers{f.users, boom}, Tokens: f.tokens, Sessions: sessions,
		Notifier: f.notifier, Audit: f.audit, Now: f.clock.Now,
	})
	token := f.request(t, "carol")

	require.ErrorIs(t, f.reset(token, newPassword), boom)
	require.NotContains(t, f.audit.actions(), "user.password_reset")
	require.Equal(t, domain.NotificationPasswordReset, f.notifier.last().Kind, "no \"password changed\" e-mail")
	require.Empty(t, observer.calls(), "nothing is told after a rollback: the trusted devices stay")
}

type failingPasswordUsers struct {
	*memUsers
	err error
}

func (u failingPasswordUsers) Update(ctx context.Context, id string, p repository.UpdateUserParams) (*domain.User, error) {
	if p.PasswordHash != nil {
		return nil, u.err
	}
	return u.memUsers.Update(ctx, id, p)
}
