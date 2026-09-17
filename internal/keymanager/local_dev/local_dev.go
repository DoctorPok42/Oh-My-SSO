package localdev

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
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
}

var _ keymanager.KeyManager = (*KeyManager)(nil)


func New(env string) *KeyManager {
	if env == "production" {
		panic("keymanager/local_dev: never use this backend with env=production")
	}
	return &KeyManager{keys: make(map[string]storedKey)}
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
	switch {
	case sk.rsaKey != nil:
		return rsa.SignPKCS1v15(rand.Reader, sk.rsaKey, crypto.SHA256, hash[:])
	case sk.ecKey != nil:
		return ecdsa.SignASN1(rand.Reader, sk.ecKey, hash[:])
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