package entstore_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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


func TestSigningKeyRepository_PendingAndCertificate(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	repo := entstore.NewSigningKeyRepository(client)

	k, err := repo.Create(ctx, repository.CreateSigningKeyParams{
		RealmID: realm.ID, KeyType: domain.SigningKeyRSA, Purpose: domain.SigningKeyPurposeSAMLSigning,
		KMSKeyReference: "ref-" + uuid.NewString(), KMSBackend: "local_dev", Kid: uuid.NewString(),
		Certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		Status:      domain.SigningKeyPending,
	})
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyPending, k.Status)
	require.Contains(t, k.Certificate, "BEGIN CERTIFICATE")

	listed, err := repo.ListActiveByRealm(ctx, realm.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1, "a pending key is published")

	require.NoError(t, repo.Activate(ctx, k.ID))
	got, err := repo.GetByID(ctx, k.ID)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyActive, got.Status)
	require.ErrorIs(t, repo.Activate(ctx, k.ID), repository.ErrNotFound, "only a pending key can be activated")
}

func TestSAMLKeyRotation_Integration(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	keys := entstore.NewSigningKeyRepository(client)
	logs := entstore.NewKeyRotationLogRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	km := localdev.New("test")
	rot := service.NewKeyRotationService(keys, logs, settings, km, "local_dev")
	idp := service.NewIdentityCore(service.IdentityCoreDeps{SigningKeys: keys, KeyManager: km})

	first, err := rot.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test", Purpose: domain.SigningKeyPurposeSAMLSigning})
	require.NoError(t, err)
	staged, err := rot.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: "test", Purpose: domain.SigningKeyPurposeSAMLSigning})
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyPending, staged.NewKey.Status)

	block, _ := pem.Decode([]byte(staged.NewKey.Certificate))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, staged.NewKey.Kid, cert.Subject.SerialNumber, "the certificate survives the round trip")

	published, err := idp.PublicKeys(ctx, realm.ID, domain.SigningKeyPurposeSAMLSigning)
	require.NoError(t, err)
	require.Len(t, published, 2)
	s, err := idp.Signer(ctx, realm.ID, domain.SigningKeyPurposeSAMLSigning)
	require.NoError(t, err)
	require.Equal(t, first.NewKey.Kid, s.KeyID())

	res, err := rot.Activate(ctx, service.ActivateInput{RealmID: realm.ID, TriggeredBy: "test"})
	require.NoError(t, err)
	require.Equal(t, staged.NewKey.Kid, res.NewKey.Kid)
	s, err = idp.Signer(ctx, realm.ID, domain.SigningKeyPurposeSAMLSigning)
	require.NoError(t, err)
	require.Equal(t, staged.NewKey.Kid, s.KeyID())
	history, err := logs.ListBySigningKey(ctx, staged.NewKey.ID)
	require.NoError(t, err)
	require.Equal(t, domain.KeyRotationActivated, history[0].Action)
}

func TestTokenRepository_SessionParticipant_Integration(t *testing.T) {
	f := newRBACFixture(t)
	tokens := entstore.NewTokenRepository(f.client)
	u := f.user()
	app := f.clientApp("saml-participant")
	sess, err := entstore.NewSessionRepository(f.client).Create(f.ctx, repository.CreateSessionParams{
		RealmID: f.realm.ID, UserID: u.ID, TokenHash: "hash-" + f.suffix(),
		ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword,
	})
	require.NoError(t, err)

	tok, err := tokens.Create(f.ctx, repository.CreateTokenParams{
		SessionID: sess.ID, ClientRefID: app.ID, Type: domain.TokenSAMLSession, JTI: "_sidx-" + f.suffix(),
		ExpiresAt: sess.ExpiresAt, Subject: "_transient-" + f.suffix(), SubjectFormat: domain.NameIDFormatTransient,
	})
	require.NoError(t, err)
	got, err := tokens.GetByJTI(f.ctx, tok.JTI)
	require.NoError(t, err)
	require.Equal(t, domain.TokenSAMLSession, got.Type)
	require.Equal(t, tok.Subject, got.Subject)
	require.Equal(t, domain.NameIDFormatTransient, got.SubjectFormat)
}
