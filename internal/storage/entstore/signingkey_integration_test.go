package entstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/storage/entstore"
)


func newTestSigningKey(t *testing.T, ctx context.Context, repo repository.SigningKeyRepository, realmID string) *domain.SigningKey {
	t.Helper()
	k, err := repo.Create(ctx, repository.CreateSigningKeyParams{
		RealmID: realmID, KeyType: domain.SigningKeyRSA, Purpose: domain.SigningKeyPurposeJWT,
		KMSKeyReference: "ref-" + uuid.NewString(), KMSBackend: "local_dev",
		PublicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n", Kid: uuid.NewString(),
	})
	require.NoError(t, err)
	return k
}

func TestSigningKeyRepository_StatusTransitions(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	repo := entstore.NewSigningKeyRepository(client)

	k := newTestSigningKey(t, ctx, repo, realm.ID)
	require.Equal(t, domain.SigningKeyActive, k.Status)
	require.True(t, k.RetireAfter.IsZero())

	deadline := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond) // Postgres precision
	require.NoError(t, repo.MarkRotating(ctx, k.ID, deadline))

	got, err := repo.GetByID(ctx, k.ID)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyRotating, got.Status)
	require.True(t, deadline.Equal(got.RetireAfter))

	// Conditional updates: a key that is no longer active cannot be marked
	// rotating again (that would move its deadline).
	require.ErrorIs(t, repo.MarkRotating(ctx, k.ID, deadline.Add(time.Hour)), repository.ErrNotFound)

	require.NoError(t, repo.Retire(ctx, k.ID))
	got, err = repo.GetByID(ctx, k.ID)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyRetired, got.Status)
	require.False(t, got.RetiredAt.IsZero())

	// A retired key never comes back.
	require.ErrorIs(t, repo.Retire(ctx, k.ID), repository.ErrNotFound)
	require.ErrorIs(t, repo.MarkRotating(ctx, k.ID, deadline), repository.ErrNotFound)
	require.ErrorIs(t, repo.MarkRotating(ctx, uuid.NewString(), deadline), repository.ErrNotFound)
}

func TestSigningKeyRepository_Lists(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	other := newTestRealm(t, ctx, client)
	repo := entstore.NewSigningKeyRepository(client)

	k1 := newTestSigningKey(t, ctx, repo, realm.ID)
	k2 := newTestSigningKey(t, ctx, repo, realm.ID)
	k3 := newTestSigningKey(t, ctx, repo, realm.ID)
	newTestSigningKey(t, ctx, repo, other.ID)
	require.NoError(t, repo.Retire(ctx, k1.ID))

	all, err := repo.ListByRealm(ctx, realm.ID)
	require.NoError(t, err)
	require.Len(t, all, 3, "retired included, other realm excluded")
	require.Equal(t, k3.ID, all[0].ID, "newest first")

	active, err := repo.ListActiveByRealm(ctx, realm.ID)
	require.NoError(t, err)
	ids := []string{active[0].ID, active[1].ID}
	require.ElementsMatch(t, []string{k2.ID, k3.ID}, ids)
}

func TestInstanceSettings_KeyRotationGraceHours(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	repo := entstore.NewInstanceSettingsRepository(client)

	s, err := repo.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: realm.ID})
	require.NoError(t, err)
	require.Equal(t, 24, s.KeyRotationGraceHours, "column default")

	hours := 72
	s, err = repo.Update(ctx, s.ID, repository.UpdateInstanceSettingsParams{KeyRotationGraceHours: &hours})
	require.NoError(t, err)
	require.Equal(t, 72, s.KeyRotationGraceHours)
}

// The whole rotation, on Postgres: service + Ent repositories + local_dev KMS.
func TestKeyRotation_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)

	keys := entstore.NewSigningKeyRepository(client)
	logs := entstore.NewKeyRotationLogRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	_, err := settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: realm.ID})
	require.NoError(t, err)

	km := localdev.New("test")
	rot := service.NewKeyRotationService(keys, logs, settings, km, "local_dev")
	core := service.NewIdentityCore(service.IdentityCoreDeps{SigningKeys: keys, KeyManager: km})

	first, err := rot.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test"})
	require.NoError(t, err)
	second, err := rot.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test"})
	require.NoError(t, err)

	require.Equal(t, 24*time.Hour, second.Grace, "from InstanceSettings")
	require.Len(t, second.Rotating, 1)
	require.Equal(t, first.NewKey.Kid, second.Rotating[0].Kid)

	published, err := core.PublicKeys(ctx, realm.ID, domain.SigningKeyPurposeJWT)
	require.NoError(t, err)
	require.Len(t, published, 2)
	require.Equal(t, second.NewKey.Kid, published[0].Kid)

	signer, err := core.Signer(ctx, realm.ID, domain.SigningKeyPurposeJWT)
	require.NoError(t, err)
	require.Equal(t, second.NewKey.Kid, signer.KeyID())

	history, err := logs.ListBySigningKey(ctx, first.NewKey.ID)
	require.NoError(t, err)
	require.Len(t, history, 2)
	require.Equal(t, domain.KeyRotationRotated, history[0].Action, "newest log first")
	require.Equal(t, domain.KeyRotationCreated, history[1].Action)
}
