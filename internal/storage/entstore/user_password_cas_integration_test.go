package entstore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestUserRepository_CompareAndSwapPasswordHash_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)

	name := "cas-" + uuid.NewString()[:8]
	u, err := users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: name, Email: name + "@example.test",
		PasswordHash: "hash-1", Status: domain.UserActive,
	})
	require.NoError(t, err)

	ok, err := users.CompareAndSwapPasswordHash(ctx, u.ID, "hash-1", "hash-2")
	require.NoError(t, err)
	require.True(t, ok)

	// A stale "old" value (the password changed in between): nothing is written.
	ok, err = users.CompareAndSwapPasswordHash(ctx, u.ID, "hash-1", "hash-3")
	require.NoError(t, err)
	require.False(t, ok)

	got, err := users.GetByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, "hash-2", got.PasswordHash)

	ok, err = users.CompareAndSwapPasswordHash(ctx, "no-such-user", "hash-2", "hash-3")
	require.NoError(t, err)
	require.False(t, ok)
}
