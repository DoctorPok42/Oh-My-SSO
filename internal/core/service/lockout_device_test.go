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

// Audit B-14: a lock caused by someone who only knows the identifier does
// not hold the devices the user already signed in from.

// signInHistory: the devices dave signed in from (their sessions).
type signInHistory struct {
	devices []string // fingerprints
	err     error
	calls   int
}

func (h *signInHistory) ListRecentByUser(_ context.Context, userID string, since time.Time, limit int) ([]*domain.Session, error) {
	h.calls++
	if h.err != nil {
		return nil, h.err
	}
	out := []*domain.Session{}
	for i, fp := range h.devices {
		out = append(out, &domain.Session{ID: "s" + string(rune('a'+i)), UserID: userID, DeviceFingerprint: fp, CreatedAt: since.Add(time.Hour)})
	}
	return out, nil
}

var (
	davesLaptop = service.DeviceFingerprint("LAPTOPAAAAAAAAAAAAAAAAAAAA")
	strangerPC  = service.DeviceFingerprint("STRANGERBBBBBBBBBBBBBBBBBB")
)

type deviceFixture struct {
	*lockoutFixture
	history *signInHistory
	store   *lockoutstore.Memory
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	f := &deviceFixture{lockoutFixture: newLockoutFixture(t, nil), history: &signInHistory{devices: []string{davesLaptop}}}
	f.store = lockoutstore.NewMemory(f.clock.Now)
	lockout := service.NewLockoutService(service.LockoutDeps{
		Users:    f.users,
		Unknown:  f.store,
		History:  f.history,
		Notifier: f.notifier,
		Audit:    f.audit,
		Now:      f.clock.Now,
	})
	f.auth = service.NewAuthService(f.users, f.attempts, service.WithLockout(lockout))
	return f
}

// from signs in to dave from a device ("" = no device cookie).
func (f *deviceFixture) from(device, password string) error {
	_, err := f.auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
		RealmID: resetRealm, Identifier: "dave", Password: password, IPAddress: "198.51.100.9",
		DeviceFingerprint: device,
	})
	return err
}

func (f *deviceFixture) lockFrom(t *testing.T, device string) {
	t.Helper()
	for i := 0; i < 5; i++ {
		require.ErrorIs(t, f.from(device, "wrong"), service.ErrInvalidCredentials, "try %d", i+1)
	}
	lockedUntil(t, f.from(device, alicePassword))
}

func TestLockout_KnownDeviceGoesPastALockCausedElsewhere(t *testing.T) {
	f := newDeviceFixture(t)
	f.lockFrom(t, "") // an attacker who only knows "dave", no cookie
	lockedUntil(t, f.from(strangerPC, alicePassword))

	// Dave, on his laptop: signed in, despite the lock.
	require.NoError(t, f.from(davesLaptop, alicePassword))

	// The lock stays for everyone else, and still says so.
	require.True(t, f.users.get("u-dave").Lockout.LockedAt(f.clock.Now()), "a sign-in past the lock does not lift it")
	lockedUntil(t, f.from("", alicePassword))
	require.Equal(t, []domain.NotificationKind{domain.NotificationAccountLocked}, f.notifier.kinds(), "dave was told about the lock")

	// A wrong password on the laptop is checked, and counted.
	require.ErrorIs(t, f.from(davesLaptop, "wrong"), service.ErrInvalidCredentials)
}

func TestLockout_UnknownDeviceStaysLocked(t *testing.T) {
	f := newDeviceFixture(t)
	f.lockFrom(t, "")
	// A cookie alone proves nothing: the device must have signed in as dave.
	lockedUntil(t, f.from(strangerPC, alicePassword))
	f.history.devices = append(f.history.devices, strangerPC) // ... once it has, it goes on
	require.NoError(t, f.from(strangerPC, alicePassword))
}

func TestLockout_KnownDeviceThatFailedItselfStaysLocked(t *testing.T) {
	f := newDeviceFixture(t)
	// Someone at dave's laptop guesses: the account locks, and so does the laptop.
	f.lockFrom(t, davesLaptop)
	lockedUntil(t, f.from(davesLaptop, alicePassword))
	require.Equal(t, 1, len(f.notifier.kinds()), "the account lock e-mail, as before")

	// The lock ends: the right password on the laptop forgets both counters.
	f.clock.Advance(15 * time.Minute)
	require.NoError(t, f.from(davesLaptop, alicePassword))
	require.True(t, f.users.get("u-dave").Lockout.IsZero())
	st, err := f.store.Get(context.Background(), service.DeviceLockoutKey(resetRealm, "u-dave", davesLaptop))
	require.NoError(t, err)
	require.True(t, st.IsZero(), "the laptop's own counter is forgotten too")
}

func TestLockout_KnownDeviceBudget(t *testing.T) {
	f := newDeviceFixture(t)
	// Two typos on the laptop, then an attacker locks the account.
	for i := 0; i < 2; i++ {
		require.ErrorIs(t, f.from(davesLaptop, "wrong"), service.ErrInvalidCredentials)
	}
	for i := 0; i < 3; i++ {
		require.ErrorIs(t, f.from("", "wrong"), service.ErrInvalidCredentials)
	}
	lockedUntil(t, f.from("", alicePassword))

	// The laptop goes on with what is left of its own budget (5 - 2 = 3).
	for i := 0; i < 3; i++ {
		require.ErrorIs(t, f.from(davesLaptop, "wrong"), service.ErrInvalidCredentials, "laptop try %d", i+1)
	}
	lockedUntil(t, f.from(davesLaptop, alicePassword))
}

func TestLockout_HistoryErrorKeepsTheLock(t *testing.T) {
	f := newDeviceFixture(t)
	f.lockFrom(t, "")
	f.history.err = errors.New("database down")
	lockedUntil(t, f.from(davesLaptop, alicePassword))
}

func TestLockout_NoLockNoHistoryRead(t *testing.T) {
	f := newDeviceFixture(t)
	require.NoError(t, f.from(davesLaptop, alicePassword))
	require.Zero(t, f.history.calls, "the usual sign-in reads no history")
}

func TestLockout_UnlockLiftsTheLockEverywhere(t *testing.T) {
	f := newDeviceFixture(t)
	f.lockFrom(t, davesLaptop)
	unlock := service.NewLockoutService(service.LockoutDeps{Users: f.users, Unknown: f.store, Now: f.clock.Now})
	require.NoError(t, unlock.Unlock(context.Background(), f.users.get("u-dave")))
	// The laptop's own counter only matters while the account is locked.
	require.NoError(t, f.from(davesLaptop, alicePassword))
	require.NoError(t, f.from("", alicePassword))
}
