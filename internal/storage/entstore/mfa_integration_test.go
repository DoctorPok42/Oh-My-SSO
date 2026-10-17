package entstore_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 9a: the guarantees the MFA services rely on, checked against a real
// Postgres (conditional updates, transactions, the partial unique index).

func newMFATestUser(t *testing.T, ctx context.Context, realmID string) *domain.User {
	t.Helper()
	client := newTestClient(t)
	name := "mfa-" + uuid.NewString()[:8]
	u, err := entstore.NewUserRepository(client).Create(ctx, repository.CreateUserParams{
		RealmID: realmID, Username: name, Email: name + "@example.test", Status: domain.UserActive,
	})
	require.NoError(t, err)
	return u
}

func TestMfaMethodRepository_TOTPLifecycle(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	user := newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewMfaMethodRepository(client)
	now := time.Now().UTC().Truncate(time.Microsecond)

	first, err := repo.Create(ctx, repository.CreateMfaMethodParams{UserID: user.ID, Type: domain.MfaMethodTOTP, Name: "old phone", Status: domain.MfaMethodPending, SecretEncrypted: "sealed-1"})
	require.NoError(t, err)
	require.Equal(t, domain.MfaMethodPending, first.Status)
	require.Equal(t, "old phone", first.Name)

	_, err = repo.ConsumeTOTPCounter(ctx, first.ID, 10, now)
	require.NoError(t, err)
	got, _ := repo.GetByID(ctx, first.ID)
	require.Zero(t, got.LastUsedCounter, "a pending TOTP never accepts a code")

	act, err := repo.ActivateTOTP(ctx, first.ID, 100, now)
	require.NoError(t, err)
	require.Equal(t, domain.MfaMethodActive, act.Status)
	require.EqualValues(t, 100, act.LastUsedCounter)

	_, err = repo.ActivateTOTP(ctx, first.ID, 101, now)
	require.ErrorIs(t, err, repository.ErrNotFound, "already active: not pending anymore")

	// Counter only moves forward.
	ok, err := repo.ConsumeTOTPCounter(ctx, first.ID, 100, now)
	require.NoError(t, err)
	require.False(t, ok, "same time step = replay")
	ok, err = repo.ConsumeTOTPCounter(ctx, first.ID, 99, now)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = repo.ConsumeTOTPCounter(ctx, first.ID, 101, now)
	require.NoError(t, err)
	require.True(t, ok)

	// Replacing the phone: the new TOTP becomes active, the old one is gone.
	second, err := repo.Create(ctx, repository.CreateMfaMethodParams{UserID: user.ID, Type: domain.MfaMethodTOTP, Status: domain.MfaMethodPending, SecretEncrypted: "sealed-2"})
	require.NoError(t, err)
	_, err = repo.ActivateTOTP(ctx, second.ID, 200, now)
	require.NoError(t, err)
	list, err := repo.ListByUser(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, second.ID, list[0].ID)

	// The partial unique index refuses a second ACTIVE TOTP...
	_, err = repo.Create(ctx, repository.CreateMfaMethodParams{UserID: user.ID, Type: domain.MfaMethodTOTP, SecretEncrypted: "sealed-3"})
	require.Error(t, err, "one active TOTP per user")
	// ...but allows a pending one, and other types.
	_, err = repo.Create(ctx, repository.CreateMfaMethodParams{UserID: user.ID, Type: domain.MfaMethodTOTP, Status: domain.MfaMethodPending, SecretEncrypted: "sealed-4"})
	require.NoError(t, err)
	n, err := repo.DeletePendingByUser(ctx, user.ID, domain.MfaMethodTOTP)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	n, err = repo.DeleteByUser(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = repo.GetByID(ctx, second.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
}

func TestMfaMethodRepository_ConcurrentReplay(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	user := newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewMfaMethodRepository(client)

	m, err := repo.Create(ctx, repository.CreateMfaMethodParams{UserID: user.ID, Type: domain.MfaMethodTOTP, Status: domain.MfaMethodPending, SecretEncrypted: "s"})
	require.NoError(t, err)
	_, err = repo.ActivateTOTP(ctx, m.ID, 1, time.Now())
	require.NoError(t, err)

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.ConsumeTOTPCounter(ctx, m.ID, 500, time.Now())
			if err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, wins, "ten requests with the same code: exactly one accepted")
}

func TestMfaBackupCodeRepository(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	user := newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewMfaBackupCodeRepository(client)

	require.NoError(t, repo.ReplaceForUser(ctx, user.ID, "batch-1", []string{"h1", "h2", "h3"}))
	unused, err := repo.ListUnusedByUser(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, unused, 3)

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := repo.ConsumeIfUnused(ctx, unused[0].ID); err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, wins, "a backup code is consumed exactly once")

	unused, err = repo.ListUnusedByUser(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, unused, 2)

	require.NoError(t, repo.ReplaceForUser(ctx, user.ID, "batch-2", []string{"h4", "h5"}))
	all, err := repo.ListByUser(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, all, 2, "the old batch is gone, used codes included")
	for _, c := range all {
		require.Equal(t, "batch-2", c.BatchID)
	}

	n, err := repo.DeleteByUser(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, 2, n)
}

func TestMfaPolicyRepository(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	roles := entstore.NewRoleRepository(client)
	role, err := roles.Create(ctx, repository.CreateRoleParams{RealmID: realm.ID, Name: "admin-" + uuid.NewString()[:6]})
	require.NoError(t, err)
	repo := entstore.NewMfaPolicyRepository(client)
	since := time.Now().UTC().Truncate(time.Second)

	p, err := repo.Upsert(ctx, repository.UpsertMfaPolicyParams{
		RealmID: realm.ID, RoleID: role.ID, Required: true, EnrollmentGraceDays: 7,
		AllowedMethods: []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodTOTP}, RequiredSince: since,
	})
	require.NoError(t, err)
	require.Equal(t, domain.MfaPolicyManagedByUI, p.ManagedBy)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodTOTP}, p.AllowedMethods)
	require.True(t, since.Equal(p.RequiredSince))

	p2, err := repo.Upsert(ctx, repository.UpsertMfaPolicyParams{RealmID: realm.ID, RoleID: role.ID, StepUpForSensitiveActions: true})
	require.NoError(t, err)
	require.Equal(t, p.ID, p2.ID, "one policy per role: updated in place")
	require.False(t, p2.Required)
	require.Nil(t, p2.AllowedMethods)
	require.True(t, p2.RequiredSince.IsZero())
	require.True(t, p2.StepUpForSensitiveActions)

	list, err := repo.ListByRoleIDs(ctx, []string{role.ID, "unknown"})
	require.NoError(t, err)
	require.Len(t, list, 1)
	inRealm, err := repo.ListByRealm(ctx, realm.ID)
	require.NoError(t, err)
	require.Len(t, inRealm, 1)

	// Deleting the role deletes its policy (ON DELETE CASCADE).
	require.NoError(t, roles.Delete(ctx, role.ID))
	_, err = repo.GetByRole(ctx, role.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
	require.ErrorIs(t, repo.DeleteByRole(ctx, role.ID), repository.ErrNotFound)
}

func TestSessionRepository_MarkMFAVerified(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	user := newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewSessionRepository(client)

	s, err := repo.Create(ctx, repository.CreateSessionParams{
		RealmID: realm.ID, UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour),
		AuthMethod: domain.AuthMethodPassword, TokenHash: uuid.NewString(),
	})
	require.NoError(t, err)
	require.False(t, s.MFAVerified)
	require.True(t, s.MFAVerifiedAt.IsZero())

	at := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.MarkMFAVerified(ctx, s.ID, "totp", at))
	got, err := repo.GetByID(ctx, s.ID)
	require.NoError(t, err)
	require.True(t, got.MFAVerified)
	require.Equal(t, "totp", got.MFAMethodType)
	require.True(t, at.Equal(got.MFAVerifiedAt))

	require.NoError(t, repo.Revoke(ctx, s.ID, domain.SessionRevokedUserLogout))
	require.ErrorIs(t, repo.MarkMFAVerified(ctx, s.ID, "totp", at), repository.ErrNotFound, "a revoked session cannot be upgraded")
}

func TestClientRepository_MFAPolicy(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	repo := entstore.NewClientRepository(client)

	c, err := repo.Create(ctx, repository.CreateClientAppParams{RealmID: realm.ID, Name: "app", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)
	require.Equal(t, domain.ClientAppMFAInherit, c.MFAPolicy, "default")
	require.Nil(t, c.MFAAllowedMethods)

	required := domain.ClientAppMFARequired
	c, err = repo.Update(ctx, c.ID, repository.UpdateClientAppParams{MFAPolicy: &required, MFAAllowedMethods: []domain.MfaMethodType{domain.MfaMethodTOTP}})
	require.NoError(t, err)
	require.Equal(t, required, c.MFAPolicy)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodTOTP}, c.MFAAllowedMethods)

	name := "renamed"
	c, err = repo.Update(ctx, c.ID, repository.UpdateClientAppParams{Name: &name})
	require.NoError(t, err)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodTOTP}, c.MFAAllowedMethods, "nil = unchanged")

	c, err = repo.Update(ctx, c.ID, repository.UpdateClientAppParams{MFAAllowedMethods: []domain.MfaMethodType{}})
	require.NoError(t, err)
	require.Nil(t, c.MFAAllowedMethods, "empty slice = cleared")
}

func TestMfaMethodRepository_WebAuthn(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	alice := newMFATestUser(t, ctx, realm.ID)
	bob := newMFATestUser(t, ctx, realm.ID)
	repo := entstore.NewMfaMethodRepository(client)
	credID := "cred-" + uuid.NewString()

	m, err := repo.Create(ctx, repository.CreateMfaMethodParams{
		UserID: alice.ID, Type: domain.MfaMethodPasskey, Name: "iPhone", CredentialID: credID,
		PublicKey: "pk", IsDiscoverable: true, WebAuthnCredential: `{"signCount":0}`,
	})
	require.NoError(t, err)
	require.Equal(t, `{"signCount":0}`, m.WebAuthnCredential)

	// Several passkeys per user are fine (one per device)...
	_, err = repo.Create(ctx, repository.CreateMfaMethodParams{UserID: alice.ID, Type: domain.MfaMethodPasskey, CredentialID: "cred-" + uuid.NewString()})
	require.NoError(t, err)
	// ...but a credential id exists once, whoever registers it.
	_, err = repo.Create(ctx, repository.CreateMfaMethodParams{UserID: bob.ID, Type: domain.MfaMethodWebAuthn, CredentialID: credID})
	require.ErrorIs(t, err, repository.ErrConflict)

	at := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.UpdateWebAuthnCredential(ctx, m.ID, `{"signCount":5}`, at))
	got, err := repo.GetByID(ctx, m.ID)
	require.NoError(t, err)
	require.Equal(t, `{"signCount":5}`, got.WebAuthnCredential)
	require.True(t, at.Equal(got.LastUsedAt))
	require.ErrorIs(t, repo.UpdateWebAuthnCredential(ctx, "missing", "{}", at), repository.ErrNotFound)
}
