package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/lockoutstore"
)

// Step 12: account lockout through AuthService.AuthenticateLocal.

type lockoutFixture struct {
	clock    *testClock
	users    *memUsers
	notifier *recordingNotifier
	audit    *fakeAuditRepo
	attempts *fakeLoginAttemptRepo
	auth     *service.AuthService
}

func newLockoutFixture(t *testing.T, settings *domain.InstanceSettings) *lockoutFixture {
	t.Helper()
	f := &lockoutFixture{clock: newTestClock(), notifier: &recordingNotifier{}, audit: &fakeAuditRepo{}, attempts: &fakeLoginAttemptRepo{}}
	f.users = newMemUsers(&domain.User{
		ID: "u-dave", RealmID: resetRealm, Username: "dave", Email: "dave@example.test",
		PasswordHash: alicePasswordHash(t), Status: domain.UserActive,
	})
	lockout := service.NewLockoutService(service.LockoutDeps{
		Users:    f.users,
		Unknown:  lockoutstore.NewMemory(f.clock.Now),
		Settings: &memSettings{s: settings},
		Notifier: f.notifier,
		Audit:    f.audit,
		Now:      f.clock.Now,
	})
	f.auth = service.NewAuthService(f.users, f.attempts, service.WithLockout(lockout))
	return f
}

func (f *lockoutFixture) try(identifier, password string) error {
	_, err := f.auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
		RealmID: resetRealm, Identifier: identifier, Password: password, IPAddress: "198.51.100.9",
	})
	return err
}

func lockedUntil(t *testing.T, err error) time.Time {
	t.Helper()
	var le *service.AccountLockedError
	require.True(t, errors.As(err, &le), "want AccountLockedError, got %v", err)
	require.ErrorIs(t, err, service.ErrAccountLocked)
	return le.Until
}

func TestLockout_LocksAfterThreshold(t *testing.T) {
	f := newLockoutFixture(t, nil) // no settings row: 5 tries, 15 minutes
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials, "try %d", i+1)
	}
	// Locked: even the right password is refused, without being checked.
	until := lockedUntil(t, f.try("dave", alicePassword))
	require.Equal(t, f.clock.Now().Add(15*time.Minute), until)
	require.Equal(t, domain.LoginFailureAccountLocked, f.attempts.last().FailureReason)

	// One e-mail and one AuditLog entry, for the lock itself.
	require.Equal(t, []domain.NotificationKind{domain.NotificationAccountLocked}, f.notifier.kinds())
	e := f.notifier.last()
	require.Equal(t, 5, e.FailedAttempts)
	require.Equal(t, until, e.ExpiresAt)
	require.Equal(t, "198.51.100.9", e.IPAddress)
	require.Contains(t, f.audit.actions(), "account_locked")

	// The lock ends on its own.
	f.clock.Advance(15 * time.Minute)
	require.NoError(t, f.try("dave", alicePassword))
	require.True(t, f.users.get("u-dave").Lockout.IsZero(), "a successful login clears everything")
}

func TestLockout_UnknownIdentifierBehavesTheSame(t *testing.T) {
	f := newLockoutFixture(t, nil)
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, f.try("ghost", "wrong"), service.ErrInvalidCredentials)
	}
	until := lockedUntil(t, f.try("ghost", "wrong"))
	require.Equal(t, f.clock.Now().Add(15*time.Minute), until, "same duration as a real account")
	require.Empty(t, f.notifier.kinds(), "nobody to e-mail")
	require.Equal(t, domain.LoginFailureUnknownAccount, f.attempts.last().FailureReason)

	// Case and spaces do not give an attacker a fresh counter.
	lockedUntil(t, f.try(" GHOST ", "wrong"))
}

func TestLockout_SuccessResetsTheCounter(t *testing.T) {
	f := newLockoutFixture(t, nil)
	for i := 0; i < 4; i++ {
		require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials)
	}
	require.NoError(t, f.try("dave", alicePassword))
	for i := 0; i < 4; i++ {
		require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials, "counting starts again")
	}
	require.NoError(t, f.try("dave", alicePassword))
}

func TestLockout_OldFailuresDoNotCount(t *testing.T) {
	f := newLockoutFixture(t, nil)
	for i := 0; i < 4; i++ {
		require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials)
	}
	f.clock.Advance(16 * time.Minute) // longer than the observation window
	require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials, "1st of a new series")
	require.NoError(t, f.try("dave", alicePassword))
}

func TestLockout_Progressive(t *testing.T) {
	f := newLockoutFixture(t, &domain.InstanceSettings{LockoutThreshold: 3, LockoutDurationMinutes: 10})
	lockOnce := func() time.Duration {
		t.Helper()
		for i := 0; i < 3; i++ {
			require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials)
		}
		until := lockedUntil(t, f.try("dave", "wrong"))
		d := until.Sub(f.clock.Now())
		f.clock.Advance(d) // wait for the end of the lock
		return d
	}
	require.Equal(t, 10*time.Minute, lockOnce())
	require.Equal(t, 20*time.Minute, lockOnce(), "a lock right after the previous one doubles")
	require.Equal(t, 40*time.Minute, lockOnce())

	// A day of calm and it starts again at the base duration.
	f.clock.Advance(25 * time.Hour)
	require.Equal(t, 10*time.Minute, lockOnce())
}

func TestLockout_Capped(t *testing.T) {
	f := newLockoutFixture(t, &domain.InstanceSettings{LockoutThreshold: 1, LockoutDurationMinutes: 600})
	var last time.Duration
	for i := 0; i < 4; i++ {
		require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials)
		until := lockedUntil(t, f.try("dave", "wrong"))
		last = until.Sub(f.clock.Now())
		f.clock.Advance(last)
	}
	require.Equal(t, 24*time.Hour, last, "10 h, 20 h, then 24 h at most")
}

func TestLockout_Disabled(t *testing.T) {
	f := newLockoutFixture(t, &domain.InstanceSettings{LockoutThreshold: 0, LockoutDurationMinutes: 15})
	for i := 0; i < 20; i++ {
		require.ErrorIs(t, f.try("dave", "wrong"), service.ErrInvalidCredentials)
	}
	require.NoError(t, f.try("dave", alicePassword))
}

func TestLockout_Unlock(t *testing.T) {
	f := newLockoutFixture(t, nil)
	lockout := service.NewLockoutService(service.LockoutDeps{Users: f.users, Now: f.clock.Now})
	for i := 0; i < 5; i++ {
		_ = f.try("dave", "wrong")
	}
	lockedUntil(t, f.try("dave", alicePassword))
	require.NoError(t, lockout.Unlock(context.Background(), f.users.get("u-dave")))
	require.NoError(t, f.try("dave", alicePassword))
}
