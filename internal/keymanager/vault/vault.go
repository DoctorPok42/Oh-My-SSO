package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"github.com/google/uuid"

	vaultapi "github.com/hashicorp/vault/api"

	"sso.internal/sso/internal/keymanager"
)

type Config struct {
	Address   string
	Token     string
	MountPath string
}

type KeyManager struct {
	client    *vaultapi.Client
	mountPath string
}

var (
	_ keymanager.KeyManager = (*KeyManager)(nil)
	_ keymanager.Encrypter  = (*KeyManager)(nil)
)

func New(cfg Config) (*KeyManager, error) {
	vc := vaultapi.DefaultConfig()
	vc.Address = cfg.Address
	client, err := vaultapi.NewClient(vc)
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: creating client: %w", err)
	}
	client.SetToken(cfg.Token)

	mount := cfg.MountPath
	if mount == "" {
		mount = "transit"
	}
	return &KeyManager{client: client, mountPath: mount}, nil
}

func (k *KeyManager) GenerateKey(ctx context.Context, keyType keymanager.KeyType) (*keymanager.GeneratedKey, error) {
	name := uuid.NewString()

	vaultType, err := toVaultKeyType(keyType)
	if err != nil {
		return nil, err
	}

	// POST /transit/keys/:name
	_, err = k.client.Logical().WriteWithContext(ctx, k.path("keys", name), map[string]interface{}{
		"type": vaultType,
	})
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: create key: %w", err)
	}

	pubPEM, err := k.readLatestPublicKey(ctx, name)
	if err != nil {
		return nil, err
	}
	return &keymanager.GeneratedKey{KMSKeyReference: name, PublicKeyPEM: pubPEM}, nil
}

func (k *KeyManager) readLatestPublicKey(ctx context.Context, name string) (string, error) {
	// GET /transit/keys/:name
	secret, err := k.client.Logical().ReadWithContext(ctx, k.path("keys", name))
	if err != nil {
		return "", fmt.Errorf("vault keymanager: read key: %w", err)
	}
	if secret == nil {
		return "", fmt.Errorf("vault keymanager: key %q not found", name)
	}

	versions, ok := secret.Data["keys"].(map[string]interface{})
	if !ok || len(versions) == 0 {
		return "", fmt.Errorf("vault keymanager: unexpected read-key response for %q", name)
	}

	var latest map[string]interface{}
	var latestVersion int
	for v, raw := range versions {
		n, _ := strconv.Atoi(v)
		if n >= latestVersion {
			latestVersion = n
			latest, _ = raw.(map[string]interface{})
		}
	}
	pub, _ := latest["public_key"].(string)
	if pub == "" {
		return "", fmt.Errorf("vault keymanager: key %q has no public_key", name)
	}
	return pub, nil
}

func (k *KeyManager) Sign(ctx context.Context, kmsKeyReference string, payload []byte) ([]byte, error) {
	// POST /transit/sign/:name
	secret, err := k.client.Logical().WriteWithContext(ctx, k.path("sign", kmsKeyReference), map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(payload),
		"signature_algorithm": "pkcs1v15",
	})
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: sign: %w", err)
	}
	raw, _ := secret.Data["signature"].(string)
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault keymanager: unexpected signature format %q", raw)
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

// GenerateEncryptionKey creates an AES-256-GCM key in Transit, used as the
// key encryption key (KEK) of envelope encryption.
// https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key
func (k *KeyManager) GenerateEncryptionKey(ctx context.Context) (string, error) {
	name := uuid.NewString()
	// POST /transit/keys/:name
	_, err := k.client.Logical().WriteWithContext(ctx, k.path("keys", name), map[string]interface{}{
		"type": "aes256-gcm96",
	})
	if err != nil {
		return "", fmt.Errorf("vault keymanager: create encryption key: %w", err)
	}
	return name, nil
}

// Encrypt returns Vault's ciphertext string ("vault:v1:...") as bytes.
// https://developer.hashicorp.com/vault/api-docs/secret/transit#encrypt-data
func (k *KeyManager) Encrypt(ctx context.Context, kmsKeyReference string, plaintext []byte) ([]byte, error) {
	// POST /transit/encrypt/:name
	secret, err := k.client.Logical().WriteWithContext(ctx, k.path("encrypt", kmsKeyReference), map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: encrypt: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("vault keymanager: encrypt: empty response")
	}
	ct, _ := secret.Data["ciphertext"].(string)
	if !strings.HasPrefix(ct, "vault:") {
		return nil, fmt.Errorf("vault keymanager: unexpected ciphertext format")
	}
	return []byte(ct), nil
}

// https://developer.hashicorp.com/vault/api-docs/secret/transit#decrypt-data
func (k *KeyManager) Decrypt(ctx context.Context, kmsKeyReference string, ciphertext []byte) ([]byte, error) {
	// POST /transit/decrypt/:name
	secret, err := k.client.Logical().WriteWithContext(ctx, k.path("decrypt", kmsKeyReference), map[string]interface{}{
		"ciphertext": string(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: decrypt: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("vault keymanager: decrypt: empty response")
	}
	pt, _ := secret.Data["plaintext"].(string)
	out, err := base64.StdEncoding.DecodeString(pt)
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: decrypt: bad plaintext encoding: %w", err)
	}
	return out, nil
}

func (k *KeyManager) path(op, name string) string {
	return fmt.Sprintf("%s/%s/%s", k.mountPath, op, name)
}

func toVaultKeyType(t keymanager.KeyType) (string, error) {
	switch t {
	case keymanager.KeyTypeRSA:
		return "rsa-2048", nil
	case keymanager.KeyTypeEC:
		return "ecdsa-p256", nil
	default:
		return "", fmt.Errorf("vault keymanager: unsupported key type %q", t)
	}
}
