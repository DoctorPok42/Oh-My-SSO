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

var _ keymanager.KeyManager = (*KeyManager)(nil)

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
