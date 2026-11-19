package keymanager

import "context"

type KeyType string

const (
	KeyTypeRSA KeyType = "rsa"
	KeyTypeEC  KeyType = "ec"
)

// KeyRemover is implemented by wallets that can delete a key. Used once a
// signing key has expired, so that it no longer lingers in the wallet.
type KeyRemover interface {
	DeleteKey(ctx context.Context, kmsKeyReference string) error
}

type GeneratedKey struct {
	KMSKeyReference string
	PublicKeyPEM string
}

// DefaultRSABits is the size of an RSA key when none is asked for.
const DefaultRSABits = 2048

// ValidRSABits tells whether a wallet may be asked for an RSA key of that
// size: 0 (DefaultRSABits), 2048, 3072 or 4096.
func ValidRSABits(bits int) bool {
	return bits == 0 || bits == 2048 || bits == 3072 || bits == 4096
}

// RSABitsOrDefault turns 0 into DefaultRSABits.
func RSABitsOrDefault(bits int) int {
	if bits == 0 {
		return DefaultRSABits
	}
	return bits
}

type KeyManager interface {
	// GenerateKey creates a key. rsaBits is the size of an RSA key (see
	// ValidRSABits; 0: DefaultRSABits) and is ignored for other key types.
	GenerateKey(ctx context.Context, keyType KeyType, rsaBits int) (*GeneratedKey, error)
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
