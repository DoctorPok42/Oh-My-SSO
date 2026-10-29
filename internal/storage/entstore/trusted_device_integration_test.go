package entstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestTrustedDeviceRepository(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)
	repo := entstore.NewTrustedDeviceRepository(client)

	newUser := func() string {
		name := "u-" + uuid.NewString()[:8]
		u, err := users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: name, Email: name + "@example.com"})
		require.NoError(t, err)
		return u.ID
	}
	t0 := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	put := func(user, device string, at time.Time, days int) *repository.PutTrustedDeviceParams {
		return &repository.PutTrustedDeviceParams{RealmID: realm.ID, UserID: user, DeviceHash: device,
			IPAddress: "203.0.113.7", UserAgent: "Firefox/140", CreatedAt: at, ExpiresAt: at.Add(time.Duration(days) * 24 * time.Hour)}
	}
	alice, bob := newUser(), newUser()
	laptop := "laptop-" + uuid.NewString()

	first, err := repo.Put(ctx, *put(alice, laptop, t0, 30))
	require.NoError(t, err)
	again, err := repo.Put(ctx, *put(alice, laptop, t0.Add(time.Hour), 7))
	require.NoError(t, err)
	got, err := repo.Get(ctx, alice, laptop)
	require.NoError(t, err)
	require.Equal(t, again.ID, got.ID)
	require.Equal(t, first.ID, got.ID, "one row per user and device")
	require.True(t, got.CreatedAt.Equal(t0.Add(time.Hour)), "ticking the box again starts a new period")
	require.True(t, got.ExpiresAt.Equal(t0.Add(time.Hour+7*24*time.Hour)))
	require.True(t, got.LastUsedAt.IsZero())

	require.NoError(t, repo.MarkUsed(ctx, got.ID, t0.Add(2*time.Hour), "198.51.100.4", "Chrome/141"))
	got, err = repo.Get(ctx, alice, laptop)
	require.NoError(t, err)
	require.True(t, got.LastUsedAt.Equal(t0.Add(2*time.Hour)))
	require.Equal(t, "198.51.100.4", got.IPAddress)
	require.ErrorIs(t, repo.MarkUsed(ctx, uuid.NewString(), t0, "", ""), repository.ErrNotFound)

	_, err = repo.Put(ctx, *put(alice, "phone", t0, 1))
	require.NoError(t, err)
	_, err = repo.Put(ctx, *put(bob, laptop, t0, 30))
	require.NoError(t, err)

	list, err := repo.ListByUser(ctx, alice, t0.Add(36*time.Hour))
	require.NoError(t, err)
	require.Len(t, list, 1, "the phone expired after one day")
	n, err := repo.DeleteExpired(ctx, alice, t0.Add(36*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = repo.Get(ctx, alice, "phone")
	require.ErrorIs(t, err, repository.ErrNotFound)

	n, err = repo.DeleteByDevice(ctx, bob, laptop)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = repo.Get(ctx, alice, laptop)
	require.NoError(t, err, "another user's trust on the same device stays")

	require.NoError(t, repo.Delete(ctx, got.ID))
	require.ErrorIs(t, repo.Delete(ctx, got.ID), repository.ErrNotFound)

	t.Run("deleted with the user", func(t *testing.T) {
		carol := newUser()
		_, err := repo.Put(ctx, *put(carol, laptop, t0, 30))
		require.NoError(t, err)
		require.NoError(t, users.Delete(ctx, carol))
		_, err = repo.Get(ctx, carol, laptop)
		require.ErrorIs(t, err, repository.ErrNotFound)
	})

	t.Run("revoked all at once", func(t *testing.T) {
		dave := newUser()
		for _, d := range []string{"a", "b", "c"} {
			_, err := repo.Put(ctx, *put(dave, d, t0, 30))
			require.NoError(t, err)
		}
		n, err := repo.DeleteByUser(ctx, dave)
		require.NoError(t, err)
		require.Equal(t, 3, n)
	})

	t.Run("8 sign-ins ticking the box at once leave one row", func(t *testing.T) {
		erin, dev := newUser(), "race-"+uuid.NewString()
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = repo.Put(ctx, *put(erin, dev, t0, 30))
			}(i)
		}
		wg.Wait()
		require.NoError(t, errors.Join(errs...))
		list, err := repo.ListByUser(ctx, erin, t0)
		require.NoError(t, err)
		require.Len(t, list, 1)
	})
}
