package entstore_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 12: the repository methods behind the lockout, the password reset
// and the sign-in history, against a real Postgres.

func TestUserRepository_CompareAndSwapLockout_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)
	u := newMFATestUser(t, ctx, realm.ID)
	require.True(t, u.Lockout.IsZero())

	now := time.Now().UTC().Truncate(time.Microsecond) // Postgres keeps microseconds
	next := domain.LockoutState{FailedCount: 1, LastFailedAt: now}

	ok, err := users.CompareAndSwapLockout(ctx, u.ID, domain.LockoutState{}, next)
	require.NoError(t, err)
	require.True(t, ok)

	// A stale "old" value no longer matches: nothing is written.
	ok, err = users.CompareAndSwapLockout(ctx, u.ID, domain.LockoutState{}, domain.LockoutState{FailedCount: 9})
	require.NoError(t, err)
	require.False(t, ok)

	got, err := users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, 1, got.Lockout.FailedCount)
	require.True(t, got.Lockout.LastFailedAt.Equal(now))

	// The state read back is a valid "old" value (times compare equal).
	locked := domain.LockoutState{LockedUntil: now.Add(15 * time.Minute), LockCount: 1, LastLockedAt: now, LastFailedAt: now}
	ok, err = users.CompareAndSwapLockout(ctx, u.ID, got.Lockout, locked)
	require.NoError(t, err)
	require.True(t, ok)

	got, err = users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.True(t, got.Lockout.LockedAt(now))
	require.Equal(t, 1, got.Lockout.LockCount)

	// Back to zero clears the nullable columns.
	ok, err = users.CompareAndSwapLockout(ctx, u.ID, got.Lockout, domain.LockoutState{})
	require.NoError(t, err)
	require.True(t, ok)
	got, err = users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.True(t, got.Lockout.IsZero())
}

func TestUserRepository_CompareAndSwapLockout_Concurrent_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)
	u := newMFATestUser(t, ctx, realm.ID)

	// 10 goroutines each add one failure with a CAS loop: none may be lost.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				cur, err := users.GetByID(ctx, u.ID)
				if err != nil {
					t.Error(err)
					return
				}
				next := cur.Lockout
				next.FailedCount++
				next.LastFailedAt = time.Now()
				ok, err := users.CompareAndSwapLockout(ctx, u.ID, cur.Lockout, next)
				if err != nil {
					t.Error(err)
					return
				}
				if ok {
					return
				}
			}
		}()
	}
	wg.Wait()
	got, err := users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, 10, got.Lockout.FailedCount)
}

func TestPasswordResetTokenRepository_ConsumeAndCancel_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	tokens := entstore.NewPasswordResetTokenRepository(client)
	u := newMFATestUser(t, ctx, realm.ID)

	t1, err := tokens.Create(ctx, repository.CreatePasswordResetTokenParams{
		UserID: u.ID, TokenHash: "hash-1-" + u.ID, ExpiresAt: time.Now().Add(time.Hour), RequestedIP: "192.0.2.1",
	})
	require.NoError(t, err)

	got, err := tokens.GetByTokenHash(ctx, "hash-1-"+u.ID)
	require.NoError(t, err)
	require.Equal(t, t1.ID, got.ID)
	require.Equal(t, "192.0.2.1", got.RequestedIP)

	_, err = tokens.GetByTokenHash(ctx, "does-not-exist")
	require.ErrorIs(t, err, repository.ErrNotFound)

	// Single use, even when two requests race.
	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := tokens.ConsumeIfUnused(ctx, t1.ID, time.Now())
			if err != nil {
				t.Error(err) // not require: FailNow must not run in a goroutine
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, wins)

	// DeleteUnusedByUser keeps the used token (history), removes the others.
	_, err = tokens.Create(ctx, repository.CreatePasswordResetTokenParams{
		UserID: u.ID, TokenHash: "hash-2-" + u.ID, ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	n, err := tokens.DeleteUnusedByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	used, err := tokens.GetByID(ctx, t1.ID)
	require.NoError(t, err)
	require.True(t, used.Used)
	require.False(t, used.UsedAt.IsZero())
}

func TestSessionRepository_ListRecentByUser_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	sessions := entstore.NewSessionRepository(client)
	u := newMFATestUser(t, ctx, realm.ID)

	for i := 0; i < 3; i++ {
		_, err := sessions.Create(ctx, repository.CreateSessionParams{
			RealmID: realm.ID, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour),
			TokenHash: "tok-" + u.ID + "-" + string(rune('a'+i)), AuthMethod: domain.AuthMethodPassword,
			DeviceFingerprint: "device-" + string(rune('a'+i)), IPAddress: "198.51.100.7",
		})
		require.NoError(t, err)
		time.Sleep(5 * time.Millisecond)
	}

	list, err := sessions.ListRecentByUser(ctx, u.ID, time.Now().Add(-time.Hour), 2)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, "device-c", list[0].DeviceFingerprint, "newest first")
	require.Equal(t, "device-b", list[1].DeviceFingerprint)

	none, err := sessions.ListRecentByUser(ctx, u.ID, time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Empty(t, none)
}
