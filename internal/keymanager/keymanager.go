package keymanager

import "context"

type KeyType string

const (
	KeyTypeRSA KeyType = "rsa"
	KeyTypeEC  KeyType = "ec"
)

type GeneratedKey struct {
	KMSKeyReference string
	PublicKeyPEM string
}

type KeyManager interface {
	GenerateKey(ctx context.Context, keyType KeyType) (*GeneratedKey, error)
	Sign(ctx context.Context, kmsKeyReference string, payload []byte) (signature []byte, err error)
}

// Encrypter is implemented by the backends that can also hold a symmetric
// "key encryption key" (KEK) for envelope encryption (Step 9).
//
// It is a separate interface on purpose: code that only signs keeps
// depending on KeyManager alone, and test fakes of KeyManager do not have to
// grow two more methods.
//
// The KEK never leaves the KMS. The application only ever asks it to
// encrypt or decrypt a small random "data key" (DEK), and does the bulk
// encryption locally with that DEK (see internal/core/service/envelope.go).
type Encrypter interface {
	// GenerateEncryptionKey creates a new symmetric key inside the KMS and
	// returns its reference (stored in SigningKey.kms_key_reference).
	GenerateEncryptionKey(ctx context.Context) (kmsKeyReference string, err error)
	// Encrypt returns an opaque ciphertext that only Decrypt with the same
	// key can turn back into plaintext.
	Encrypt(ctx context.Context, kmsKeyReference string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, kmsKeyReference string, ciphertext []byte) ([]byte, error)
}

// DigestSigner is implemented by the backends that can sign a SHA-256
// digest computed by the caller (Step 11).
//
// KeyManager.Sign hashes the payload itself, which is all a JWT needs. Two
// SAML building blocks compute the digest themselves and hand it over to a
// crypto.Signer: XML-DSig (the digest of the canonical <SignedInfo>) and
// x509.CreateCertificate (the digest of the certificate body). Same key, same
// algorithm (RSA PKCS#1 v1.5 or ECDSA with SHA-256), only the hashing step
// moves to the caller. The private key still never leaves the KMS.
type DigestSigner interface {
	// SignDigest signs a 32-byte SHA-256 digest.
	SignDigest(ctx context.Context, kmsKeyReference string, digest []byte) ([]byte, error)
}
