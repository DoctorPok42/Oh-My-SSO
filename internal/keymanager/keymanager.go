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
