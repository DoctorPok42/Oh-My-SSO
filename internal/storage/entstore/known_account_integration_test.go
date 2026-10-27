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

func TestKnownAccountRepository(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)
	repo := entstore.NewKnownAccountRepository(client)

	newUser := func() string {
		name := "u-" + uuid.NewString()[:8]
		u, err := users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: name, Email: name + "@example.com"})
		require.NoError(t, err)
		return u.ID
	}
	device := "device-" + uuid.NewString()
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	alice, bob, carol := newUser(), newUser(), newUser()

	first, err := repo.Touch(ctx, realm.ID, device, alice, t0)
	require.NoError(t, err)
	again, err := repo.Touch(ctx, realm.ID, device, alice, t0.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, first.ID, again.ID, "one row per account and device")
	require.True(t, again.LastUsedAt.Equal(t0.Add(time.Hour)))
	require.True(t, again.CreatedAt.Equal(t0))

	_, err = repo.Touch(ctx, realm.ID, device, bob, t0.Add(2*time.Hour))
	require.NoError(t, err)
	_, err = repo.Touch(ctx, realm.ID, device, carol, t0.Add(30*time.Minute))
	require.NoError(t, err)
	_, err = repo.Touch(ctx, realm.ID, "other-device", carol, t0)
	require.NoError(t, err)

	rows, err := repo.ListByDevice(ctx, realm.ID, device)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	require.Equal(t, []string{bob, alice, carol}, []string{rows[0].UserID, rows[1].UserID, rows[2].UserID}, "most recent first")

	n, err := repo.Trim(ctx, realm.ID, device, 2)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	rows, err = repo.ListByDevice(ctx, realm.ID, device)
	require.NoError(t, err)
	require.Len(t, rows, 2, "carol, the least recently used, is gone")
	other, err := repo.ListByDevice(ctx, realm.ID, "other-device")
	require.NoError(t, err)
	require.Len(t, other, 1, "another device keeps its own")

	require.NoError(t, repo.Delete(ctx, rows[0].ID))
	require.ErrorIs(t, repo.Delete(ctx, rows[0].ID), repository.ErrNotFound)
	_, err = repo.GetByID(ctx, rows[0].ID)
	require.ErrorIs(t, err, repository.ErrNotFound)

	require.NoError(t, users.Delete(ctx, alice))
	_, err = repo.GetByID(ctx, rows[1].ID)
	require.ErrorIs(t, err, repository.ErrNotFound, "deleted with the user")

	t.Run("two first sign-ins at the same time make one row", func(t *testing.T) {
		dev := "race-" + uuid.NewString()
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = repo.Touch(ctx, realm.ID, dev, bob, t0)
			}(i)
		}
		wg.Wait()
		require.NoError(t, errors.Join(errs...))
		rows, err := repo.ListByDevice(ctx, realm.ID, dev)
		require.NoError(t, err)
		require.Len(t, rows, 1)
	})
}
