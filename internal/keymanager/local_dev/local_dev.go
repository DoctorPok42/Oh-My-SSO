package localdev

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"sso.internal/sso/internal/keymanager"
)

type storedKey struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

type KeyManager struct {
	mu   sync.RWMutex
	keys map[string]storedKey

	// envelopeMaster is the root secret of the symmetric keys used for
	// envelope encryption. Each key is derived from it with HKDF and its
	// reference, so a key can be recomputed after a restart as long as the
	// same master is given back (WithEnvelopeMasterKey). Without it, a
	// random master is drawn at startup and everything it encrypted is lost
	// with the process.
	envelopeMaster []byte
}

var (
	_ keymanager.KeyManager = (*KeyManager)(nil)
	_ keymanager.Encrypter  = (*KeyManager)(nil)
	_ keymanager.DigestSigner = (*KeyManager)(nil)
)

// Option configures a local_dev KeyManager.
type Option func(*KeyManager)

// WithEnvelopeMasterKey sets the 32-byte root secret of the envelope
// encryption keys (LOCALDEV_ENVELOPE_KEY), so data encrypted in a previous
// run (TOTP secrets...) can still be decrypted after a restart.
func WithEnvelopeMasterKey(key []byte) Option {
	return func(k *KeyManager) {
		if len(key) == 32 {
			k.envelopeMaster = append([]byte(nil), key...)
		}
	}
}


func New(env string, opts ...Option) *KeyManager {
	if env == "production" {
		panic("keymanager/local_dev: never use this backend with env=production")
	}
	k := &KeyManager{keys: make(map[string]storedKey)}
	for _, opt := range opts {
		opt(k)
	}
	if k.envelopeMaster == nil {
		k.envelopeMaster = make([]byte, 32)
		_, _ = rand.Read(k.envelopeMaster) // crypto/rand.Read never fails (Go >= 1.24)
	}
	return k
}

// GenerateEncryptionKey returns a new key reference. There is nothing to
// store: the key itself is derived from the master and the reference.
func (k *KeyManager) GenerateEncryptionKey(ctx context.Context) (string, error) {
	return "aes-" + uuid.NewString(), nil
}

// Encrypt: AES-256-GCM, output = nonce (12 bytes) || ciphertext+tag.
func (k *KeyManager) Encrypt(ctx context.Context, kmsKeyReference string, plaintext []byte) ([]byte, error) {
	gcm, err := k.envelopeAEAD(kmsKeyReference)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plaintext, []byte(kmsKeyReference)), nil
}

func (k *KeyManager) Decrypt(ctx context.Context, kmsKeyReference string, ciphertext []byte) ([]byte, error) {
	gcm, err := k.envelopeAEAD(kmsKeyReference)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("local_dev keymanager: ciphertext too short")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, []byte(kmsKeyReference))
	if err != nil {
		// Most likely cause in development: the process restarted without
		// LOCALDEV_ENVELOPE_KEY, so the master key is not the same anymore.
		return nil, fmt.Errorf("local_dev keymanager: decrypt with %q failed (was LOCALDEV_ENVELOPE_KEY changed or unset?): %w", kmsKeyReference, err)
	}
	return plain, nil
}

func (k *KeyManager) envelopeAEAD(kmsKeyReference string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, k.envelopeMaster, nil, "oh-my-sso/local_dev/envelope/"+kmsKeyReference, 32)
	if err != nil {
		return nil, fmt.Errorf("local_dev keymanager: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (k *KeyManager) GenerateKey(ctx context.Context, keyType keymanager.KeyType) (*keymanager.GeneratedKey, error) {
	id := uuid.NewString()
	var sk storedKey
	var pub crypto.PublicKey

	switch keyType {
	case keymanager.KeyTypeRSA:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("local_dev keymanager: generate rsa key: %w", err)
		}
		sk.rsaKey, pub = priv, &priv.PublicKey
	case keymanager.KeyTypeEC:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("local_dev keymanager: generate ec key: %w", err)
		}
		sk.ecKey, pub = priv, &priv.PublicKey
	default:
		return nil, fmt.Errorf("local_dev keymanager: unsupported key type %q", keyType)
	}

	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		return nil, err
	}

	k.mu.Lock()
	k.keys[id] = sk
	k.mu.Unlock()

	return &keymanager.GeneratedKey{KMSKeyReference: id, PublicKeyPEM: pubPEM}, nil
}

func (k *KeyManager) Sign(ctx context.Context, kmsKeyReference string, payload []byte) ([]byte, error) {
	k.mu.RLock()
	sk, ok := k.keys[kmsKeyReference]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("local_dev keymanager: unknown key %q", kmsKeyReference)
	}

	hash := sha256.Sum256(payload)
	return signDigest(sk, kmsKeyReference, hash[:])
}

func (k *KeyManager) SignDigest(ctx context.Context, kmsKeyReference string, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("local_dev keymanager: digest must be %d bytes (SHA-256), got %d", sha256.Size, len(digest))
	}
	k.mu.RLock()
	sk, ok := k.keys[kmsKeyReference]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("local_dev keymanager: unknown key %q", kmsKeyReference)
	}
	return signDigest(sk, kmsKeyReference, digest)
}

func signDigest(sk storedKey, kmsKeyReference string, digest []byte) ([]byte, error) {
	switch {
	case sk.rsaKey != nil:
		return rsa.SignPKCS1v15(rand.Reader, sk.rsaKey, crypto.SHA256, digest)
	case sk.ecKey != nil:
		return ecdsa.SignASN1(rand.Reader, sk.ecKey, digest)
	default:
		return nil, fmt.Errorf("local_dev keymanager: key %q has no material", kmsKeyReference)
	}
}

func encodePublicKeyPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("local_dev keymanager: marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}