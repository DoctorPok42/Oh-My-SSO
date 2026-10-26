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

type Encrypter interface {
	// GenerateEncryptionKey creates a new symmetric key inside the KMS and
	// returns its reference (stored in SigningKey.kms_key_reference).
	GenerateEncryptionKey(ctx context.Context) (kmsKeyReference string, err error)
	// Encrypt returns an opaque ciphertext that only Decrypt with the same
	// key can turn back into plaintext.
	Encrypt(ctx context.Context, kmsKeyReference string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, kmsKeyReference string, ciphertext []byte) ([]byte, error)
}

type DigestSigner interface {
	// SignDigest signs a 32-byte SHA-256 digest.
	SignDigest(ctx context.Context, kmsKeyReference string, digest []byte) ([]byte, error)
}
