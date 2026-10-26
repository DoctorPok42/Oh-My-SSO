package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/keymanager"
)


var (
	ErrEnvelopeNotConfigured   = errors.New("service: envelope encryption is not configured (KMS backend cannot encrypt)")
	ErrEnvelopeCorrupted       = errors.New("service: encrypted value is malformed")
	ErrEnvelopeBackendMismatch = errors.New("service: encrypted value belongs to another KMS backend")
)

const envelopeVersion = 1

// envelopeBlob is what ends up in a TEXT column (e.g. MfaMethod.secret_encrypted).
type envelopeBlob struct {
	V     int    `json:"v"`
	Kid   string `json:"kid"` // SigningKey.Kid of the KEK, needed to decrypt and to re-encrypt one day
	DEK   string `json:"dek"` // wrapped DEK, base64
	Nonce string `json:"n"`   // AES-GCM nonce, base64
	CT    string `json:"ct"`  // ciphertext + GCM tag, base64
}

// EnvelopeService encrypts small secrets for storage.
type EnvelopeService struct {
	keys    repository.SigningKeyRepository
	enc     keymanager.Encrypter // nil: backend cannot encrypt
	backend string               // "vault", "local_dev", "ovhkms"

	mu      sync.Mutex
	current map[string]*domain.SigningKey // realmID -> KEK used for new encryptions
	byKid   map[string]*domain.SigningKey // kid -> KEK (decryption)
}

func NewEnvelopeService(keys repository.SigningKeyRepository, enc keymanager.Encrypter, backend string) *EnvelopeService {
	return &EnvelopeService{
		keys:    keys,
		enc:     enc,
		backend: backend,
		current: map[string]*domain.SigningKey{},
		byKid:   map[string]*domain.SigningKey{},
	}
}

// Seal encrypts plaintext with a fresh DEK. aad ("additional authenticated
// data") is not stored but must be given again to Open: binding a TOTP
// secret to its user id means a secret copied onto another user's row in
// the database will not decrypt.
func (s *EnvelopeService) Seal(ctx context.Context, realmID string, plaintext, aad []byte) (string, error) {
	if s == nil || s.enc == nil {
		return "", ErrEnvelopeNotConfigured
	}
	kek, err := s.currentKey(ctx, realmID)
	if err != nil {
		return "", err
	}

	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	gcm, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	wrapped, err := s.enc.Encrypt(ctx, kek.KMSKeyReference, dek)
	if err != nil {
		return "", fmt.Errorf("envelope seal: wrap data key: %w", err)
	}

	out, err := json.Marshal(envelopeBlob{
		V:     envelopeVersion,
		Kid:   kek.Kid,
		DEK:   base64.StdEncoding.EncodeToString(wrapped),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Open decrypts a value produced by Seal, with the same aad.
func (s *EnvelopeService) Open(ctx context.Context, sealed string, aad []byte) ([]byte, error) {
	if s == nil || s.enc == nil {
		return nil, ErrEnvelopeNotConfigured
	}
	var b envelopeBlob
	if err := json.Unmarshal([]byte(sealed), &b); err != nil || b.V != envelopeVersion || b.Kid == "" {
		return nil, ErrEnvelopeCorrupted
	}
	wrapped, err1 := base64.StdEncoding.DecodeString(b.DEK)
	nonce, err2 := base64.StdEncoding.DecodeString(b.Nonce)
	ct, err3 := base64.StdEncoding.DecodeString(b.CT)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, ErrEnvelopeCorrupted
	}

	kek, err := s.keyByKid(ctx, b.Kid)
	if err != nil {
		return nil, err
	}
	dek, err := s.enc.Decrypt(ctx, kek.KMSKeyReference, wrapped)
	if err != nil {
		return nil, fmt.Errorf("envelope open: unwrap data key: %w", err)
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrEnvelopeCorrupted
	}
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		// Wrong aad or tampered ciphertext: GCM authentication failed.
		return nil, fmt.Errorf("%w: authentication failed", ErrEnvelopeCorrupted)
	}
	return plain, nil
}

// currentKey returns the realm's active envelope KEK, creating it on first
// use. Two processes racing on the very first secret of a realm may each
// create one: harmless, every blob names the key it was sealed with.
func (s *EnvelopeService) currentKey(ctx context.Context, realmID string) (*domain.SigningKey, error) {
	s.mu.Lock()
	k, ok := s.current[realmID]
	s.mu.Unlock()
	if ok {
		return k, nil
	}

	keys, err := s.keys.ListActiveByRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("envelope: list keys: %w", err)
	}
	var newest *domain.SigningKey
	for _, key := range keys {
		if key.Purpose != domain.SigningKeyPurposeEnvelopeEncrypt || key.Status != domain.SigningKeyActive {
			continue
		}
		if key.KMSBackend != s.backend {
			continue // created under another backend: this process cannot use it
		}
		if newest == nil || key.CreatedAt.After(newest.CreatedAt) {
			newest = key
		}
	}

	if newest == nil {
		ref, err := s.enc.GenerateEncryptionKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("envelope: generate key: %w", err)
		}
		newest, err = s.keys.Create(ctx, repository.CreateSigningKeyParams{
			RealmID:         realmID,
			KeyType:         domain.SigningKeyAES,
			Purpose:         domain.SigningKeyPurposeEnvelopeEncrypt,
			KMSKeyReference: ref,
			KMSBackend:      s.backend,
			Kid:             uuid.NewString(),
		})
		if err != nil {
			return nil, fmt.Errorf("envelope: store key: %w", err)
		}
	}

	s.mu.Lock()
	s.current[realmID] = newest
	s.byKid[newest.Kid] = newest
	s.mu.Unlock()
	return newest, nil
}

func (s *EnvelopeService) keyByKid(ctx context.Context, kid string) (*domain.SigningKey, error) {
	s.mu.Lock()
	k, ok := s.byKid[kid]
	s.mu.Unlock()
	if !ok {
		var err error
		k, err = s.keys.GetByKid(ctx, kid)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return nil, fmt.Errorf("%w: unknown key %s", ErrEnvelopeCorrupted, kid)
			}
			return nil, fmt.Errorf("envelope: load key %s: %w", kid, err)
		}
		s.mu.Lock()
		s.byKid[kid] = k
		s.mu.Unlock()
	}
	if k.Purpose != domain.SigningKeyPurposeEnvelopeEncrypt {
		return nil, fmt.Errorf("%w: key %s is not an envelope key", ErrEnvelopeCorrupted, kid)
	}
	if k.KMSBackend != s.backend {
		return nil, fmt.Errorf("%w: key %s lives in %q, this server uses %q", ErrEnvelopeBackendMismatch, kid, k.KMSBackend, s.backend)
	}
	return k, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
