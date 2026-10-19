package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/keymanager"
)

var (
	// ErrDigestSigningUnsupported: the KeyManager backend cannot sign a
	// digest computed by the caller (keymanager.DigestSigner), which SAML
	// needs (Step 11). The three real backends can.
	ErrDigestSigningUnsupported = errors.New("service: the key manager backend cannot sign a digest (needed for SAML)")
	// ErrSAMLKeyMustBeRSA: RSA-SHA256 is the only signature algorithm every
	// SAML service provider supports, so saml_signing keys are RSA.
	ErrSAMLKeyMustBeRSA = errors.New("service: saml_signing keys must be RSA")
)

// samlCertificateValidity of the self-signed certificate of a SAML key. Its
// dates are not what ends the key's life: rotation does (Step 11). They only
// have to cover the life of the key, and many service providers refuse an
// expired IdP certificate, so they are generous.
const samlCertificateValidity = 10 * 365 * 24 * time.Hour

type GenerateSigningKeyParams struct {
	RealmID string
	KeyType domain.SigningKeyType
	Purpose domain.SigningKeyPurpose
	// Status of the new key. Empty means "active". Step 11 creates SAML keys
	// "pending" (published first, signing later).
	Status domain.SigningKeyStatus
	// Now is the clock used for the certificate dates (nil: time.Now).
	Now func() time.Time
}

func GenerateSigningKey(
	ctx context.Context,
	km keymanager.KeyManager,
	repo repository.SigningKeyRepository,
	kmsBackend string, // "vault", "local_dev", "ovhkms"
	params GenerateSigningKeyParams,
) (*domain.SigningKey, error) {
	kmType, err := toKeyManagerType(params.KeyType)
	if err != nil {
		return nil, err
	}
	saml := params.Purpose == domain.SigningKeyPurposeSAMLSigning
	if saml {
		if params.KeyType != domain.SigningKeyRSA {
			return nil, ErrSAMLKeyMustBeRSA
		}
		// Check before creating anything in the KMS.
		if _, ok := km.(keymanager.DigestSigner); !ok {
			return nil, ErrDigestSigningUnsupported
		}
	}

	generated, err := km.GenerateKey(ctx, kmType)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	kid := uuid.NewString()
	var certPEM string
	if saml {
		now := time.Now
		if params.Now != nil {
			now = params.Now
		}
		certPEM, err = selfSignedCertificate(ctx, km.(keymanager.DigestSigner), generated, kid, now())
		if err != nil {
			return nil, fmt.Errorf("generate signing key: certificate: %w", err)
		}
	}

	return repo.Create(ctx, repository.CreateSigningKeyParams{
		RealmID:         params.RealmID,
		KeyType:         params.KeyType,
		Purpose:         params.Purpose,
		KMSKeyReference: generated.KMSKeyReference,
		KMSBackend:      kmsBackend,
		PublicKey:       generated.PublicKeyPEM,
		Kid:             kid,
		Certificate:     certPEM,
		Status:          params.Status,
	})
}

// selfSignedCertificate wraps the public key of a KMS key in a self-signed
// X.509 certificate, signed BY THE KMS: the private key never leaves it.
//
// SAML publishes signing keys as certificates (<ds:X509Certificate> in the
// metadata). Nobody checks a chain: the service provider trusts this exact
// certificate because the administrator configured it. The subject carries
// the kid so that a certificate can be matched to its key by hand.
func selfSignedCertificate(ctx context.Context, ds keymanager.DigestSigner, key *keymanager.GeneratedKey, kid string, now time.Time) (string, error) {
	pub, err := parsePublicKeyPEM(key.PublicKeyPEM)
	if err != nil {
		return "", err
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		return "", ErrSAMLKeyMustBeRSA
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Oh-My-SSO SAML signing",
			SerialNumber: kid,
		},
		// A few minutes in the past: a service provider whose clock is a bit
		// late must not see a certificate "from the future".
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(samlCertificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	signer := &kmsCryptoSigner{ctx: ctx, ds: ds, ref: key.KMSKeyReference, pub: pub}
	// CreateCertificate also checks the signature it got with pub: a KMS that
	// signed with another key would be caught here.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func parsePublicKeyPEM(s string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("public key: not PEM encoded")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// kmsCryptoSigner is a crypto.Signer backed by the KMS, for the standard
// library (x509.CreateCertificate) that hands over a digest.
type kmsCryptoSigner struct {
	ctx context.Context
	ds  keymanager.DigestSigner
	ref string
	pub crypto.PublicKey
}

func (s *kmsCryptoSigner) Public() crypto.PublicKey { return s.pub }

func (s *kmsCryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("kms signer: only SHA-256 is supported, got %v", opts.HashFunc())
	}
	if _, pss := opts.(*rsa.PSSOptions); pss {
		return nil, errors.New("kms signer: RSA-PSS is not supported")
	}
	return s.ds.SignDigest(s.ctx, s.ref, digest)
}

func toKeyManagerType(t domain.SigningKeyType) (keymanager.KeyType, error) {
	switch t {
	case domain.SigningKeyRSA:
		return keymanager.KeyTypeRSA, nil
	case domain.SigningKeyEC:
		return keymanager.KeyTypeEC, nil
	default:
		return "", fmt.Errorf("unsupported signing key type %q", t)
	}
}
