package service_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/storage/memstore"
)

// Step 11 - SAML signing keys: self-signed certificate signed by the KMS,
// and the two-step rotation (Rotate = pending, Activate = signs).

func samlRotate(t *testing.T, f *rotFixture, in service.RotateInput) *service.RotateResult {
	t.Helper()
	in.Purpose = domain.SigningKeyPurposeSAMLSigning
	return f.rotate(t, in)
}

func samlPublished(t *testing.T, f *rotFixture) []string {
	t.Helper()
	keys, err := f.core.PublicKeys(context.Background(), rotRealm, domain.SigningKeyPurposeSAMLSigning)
	require.NoError(t, err)
	kids := make([]string, 0, len(keys))
	for _, k := range keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

func samlSignerKid(t *testing.T, f *rotFixture) string {
	t.Helper()
	s, err := f.core.Signer(context.Background(), rotRealm, domain.SigningKeyPurposeSAMLSigning)
	require.NoError(t, err)
	return s.KeyID()
}

func parseCert(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	require.NotNil(t, block, "PEM certificate")
	require.Equal(t, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestSAMLKey_FirstKeyIsActiveWithASelfSignedCertificate(t *testing.T) {
	f := newRotFixture(t)
	res := samlRotate(t, f, service.RotateInput{})

	k := res.NewKey
	require.Equal(t, domain.SigningKeyActive, k.Status, "nothing to replace: the first key signs at once")
	require.Equal(t, domain.SigningKeyRSA, k.KeyType)
	cert := parseCert(t, k.Certificate)
	require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature),
		"self-signed: the KMS key signed its own certificate")
	require.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
	require.Equal(t, k.Kid, cert.Subject.SerialNumber, "the subject names the key")
	require.True(t, cert.NotBefore.Before(f.now))
	require.True(t, cert.NotAfter.After(f.now.Add(9*365*24*time.Hour)))

	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(k.PublicKey))
	require.Equal(t, block.Bytes, pubDER, "the certificate carries the key's public part")

	require.Equal(t, k.Kid, samlSignerKid(t, f))
	require.Empty(t, f.publishedKids(t), "a SAML key never shows up in the JWT JWKS")
}

func TestSAMLKey_SignerSignsDigests(t *testing.T) {
	f := newRotFixture(t)
	key := samlRotate(t, f, service.RotateInput{}).NewKey

	s, err := f.core.Signer(context.Background(), rotRealm, domain.SigningKeyPurposeSAMLSigning)
	require.NoError(t, err)
	ds, ok := s.(core.DigestSigner)
	require.True(t, ok, "saml signers sign digests (XML-DSig)")
	require.Equal(t, key.Certificate, ds.CertificatePEM())

	digest := sha256.Sum256([]byte("<ds:SignedInfo>...</ds:SignedInfo>"))
	sig, err := ds.SignDigest(context.Background(), digest[:])
	require.NoError(t, err)
	pub := parseCert(t, ds.CertificatePEM()).PublicKey.(*rsa.PublicKey)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))

	_, err = ds.SignDigest(context.Background(), []byte("not a digest"))
	require.Error(t, err, "only 32-byte SHA-256 digests")
}

func TestSAMLKey_TwoStepRotation(t *testing.T) {
	ctx := context.Background()
	f := newRotFixture(t)
	f.settings.graceHours = 12
	first := samlRotate(t, f, service.RotateInput{}).NewKey

	// Step 1: the new key is published but does not sign.
	staged := samlRotate(t, f, service.RotateInput{Reason: "yearly"})
	pending := staged.NewKey
	require.Equal(t, domain.SigningKeyPending, pending.Status)
	require.Empty(t, staged.Rotating, "nothing is demoted yet")
	require.Zero(t, staged.Grace)
	require.Equal(t, []string{pending.Kid, first.Kid}, samlPublished(t, f), "both certificates in the metadata, newest first")
	require.Equal(t, first.Kid, samlSignerKid(t, f), "the current key keeps signing")
	logs, _ := f.logs.ListBySigningKey(ctx, pending.ID)
	require.Equal(t, domain.KeyRotationCreated, logs[0].Action)
	require.Contains(t, logs[0].Reason, "staged")

	// Only one pending key at a time.
	_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, Purpose: domain.SigningKeyPurposeSAMLSigning})
	require.ErrorIs(t, err, service.ErrPendingKeyExists)

	// Step 2: activation.
	f.advance(48 * time.Hour)
	res, err := f.rot.Activate(ctx, service.ActivateInput{RealmID: rotRealm, TriggeredBy: rotBy, Reason: "SPs updated"})
	require.NoError(t, err)
	require.Equal(t, pending.Kid, res.NewKey.Kid)
	require.Equal(t, domain.SigningKeyActive, f.key(t, pending.Kid).Status)
	require.Equal(t, pending.Kid, samlSignerKid(t, f), "the new key signs now")
	require.Len(t, res.Rotating, 1)
	require.Equal(t, first.Kid, res.Rotating[0].Kid)
	require.Equal(t, 12*time.Hour, res.Grace)
	old := f.key(t, first.Kid)
	require.Equal(t, domain.SigningKeyRotating, old.Status)
	require.Equal(t, f.now.Add(12*time.Hour), old.RetireAfter)
	require.Equal(t, []string{pending.Kid, first.Kid}, samlPublished(t, f), "the old certificate stays published during its grace")

	logs, _ = f.logs.ListBySigningKey(ctx, pending.ID) // newest first
	require.Equal(t, domain.KeyRotationActivated, logs[0].Action)
	require.Equal(t, "SPs updated", logs[0].Reason)
	logs, _ = f.logs.ListBySigningKey(ctx, first.ID)
	require.Equal(t, domain.KeyRotationRotated, logs[0].Action)
	require.Contains(t, logs[0].Reason, pending.Kid)

	// After the grace period, only the new certificate remains.
	f.advance(13 * time.Hour)
	require.Equal(t, []string{pending.Kid}, samlPublished(t, f))

	// Nothing left to activate.
	_, err = f.rot.Activate(ctx, service.ActivateInput{RealmID: rotRealm, TriggeredBy: rotBy})
	require.ErrorIs(t, err, service.ErrNoPendingKey)
}

func TestSAMLKey_CompromisedRotationSwitchesAtOnce(t *testing.T) {
	f := newRotFixture(t)
	first := samlRotate(t, f, service.RotateInput{}).NewKey
	pending := samlRotate(t, f, service.RotateInput{}).NewKey
	require.Equal(t, domain.SigningKeyPending, pending.Status)

	res := samlRotate(t, f, service.RotateInput{Compromised: true, Reason: "key leaked"})
	require.Equal(t, domain.SigningKeyActive, res.NewKey.Status, "an emergency never waits")
	require.Equal(t, res.NewKey.Kid, samlSignerKid(t, f))
	require.Equal(t, domain.SigningKeyRetired, f.key(t, first.Kid).Status)
	require.Equal(t, domain.SigningKeyRetired, f.key(t, pending.Kid).Status, "the pending key goes too")
	require.Equal(t, []string{res.NewKey.Kid}, samlPublished(t, f))
}

func TestSAMLKey_RefusedInputs(t *testing.T) {
	ctx := context.Background()
	f := newRotFixture(t)

	_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy,
		Purpose: domain.SigningKeyPurposeSAMLSigning, KeyType: domain.SigningKeyEC})
	require.ErrorIs(t, err, service.ErrSAMLKeyMustBeRSA)

	_, err = f.rot.Activate(ctx, service.ActivateInput{RealmID: rotRealm, TriggeredBy: rotBy, Purpose: domain.SigningKeyPurposeJWT})
	require.ErrorIs(t, err, service.ErrActivationNotSupported, "JWT keys rotate in one step")

	// A KMS that cannot sign digests cannot hold SAML keys.
	rot := service.NewKeyRotationService(memstore.NewSigningKeys(nil), memstore.NewKeyRotationLogs(nil), f.settings,
		hashOnlyKM{f.km}, "fake")
	_, err = rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, Purpose: domain.SigningKeyPurposeSAMLSigning})
	require.ErrorIs(t, err, service.ErrDigestSigningUnsupported)
}

// hashOnlyKM hides SignDigest: a KeyManager with only Sign.
type hashOnlyKM struct{ km keymanager.KeyManager }

func (h hashOnlyKM) GenerateKey(ctx context.Context, t keymanager.KeyType) (*keymanager.GeneratedKey, error) {
	return h.km.GenerateKey(ctx, t)
}
func (h hashOnlyKM) Sign(ctx context.Context, ref string, payload []byte) ([]byte, error) {
	return h.km.Sign(ctx, ref, payload)
}
