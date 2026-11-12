package entstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func newTestSession(t *testing.T, ctx context.Context, repo repository.SessionRepository, realmID, userID string) *domain.Session {
	t.Helper()
	s, err := repo.Create(ctx, repository.CreateSessionParams{
		RealmID: realmID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour),
		AuthMethod: domain.AuthMethodPassword, TokenHash: uuid.NewString(),
	})
	require.NoError(t, err)
	return s
}

func TestSessionRepository_Touch(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	user := newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewSessionRepository(client)
	s := newTestSession(t, ctx, repo, realm.ID, user.ID)

	at := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	require.NoError(t, repo.Touch(ctx, s.ID, at))
	got, err := repo.GetByID(ctx, s.ID)
	require.NoError(t, err)
	require.True(t, at.Equal(got.LastActivityAt))

	require.NoError(t, repo.Revoke(ctx, s.ID, domain.SessionRevokedAdminRevoked))
	require.ErrorIs(t, repo.Touch(ctx, s.ID, at.Add(time.Minute)), repository.ErrNotFound, "a revoked session does not look alive again")
	require.ErrorIs(t, repo.Touch(ctx, uuid.NewString(), at), repository.ErrNotFound)
}

func TestSessionRepository_RevokeAllByUser(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	user, other := newMFATestUser(t, ctx, realm.ID), newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewSessionRepository(client)
	first, second := newTestSession(t, ctx, repo, realm.ID, user.ID), newTestSession(t, ctx, repo, realm.ID, user.ID)
	kept := newTestSession(t, ctx, repo, realm.ID, other.ID)

	revoked, err := repo.RevokeAllByUser(ctx, user.ID, domain.SessionRevokedPasswordReset)
	require.NoError(t, err)
	require.Len(t, revoked, 2)
	for _, id := range []string{first.ID, second.ID} {
		got, err := repo.GetByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, domain.SessionRevoked, got.Status)
		require.Equal(t, domain.SessionRevokedPasswordReset, got.RevokedReason)
	}
	got, err := repo.GetByID(ctx, kept.ID)
	require.NoError(t, err)
	require.Equal(t, domain.SessionActive, got.Status, "another user's session is untouched")

	revoked, err = repo.RevokeAllByUser(ctx, user.ID, domain.SessionRevokedPasswordReset)
	require.NoError(t, err)
	require.Empty(t, revoked)
}
