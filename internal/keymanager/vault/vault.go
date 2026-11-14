package vault

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
	"crypto/sha256"
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
	MountPath string // Transit engine mount, default "transit"
	Namespace string // Vault Enterprise / HCP namespace, optional

	// AppRole authentication, used instead of Token when AppRoleID is set.
	// The token it yields is renewed, or replaced by a new login, before it
	// expires. The secret id is AppRoleSecretID, or the content of
	// AppRoleSecretIDFile (re-read at every login, so it can be rotated).
	AppRoleID           string
	AppRoleSecretID     string
	AppRoleSecretIDFile string
	AppRoleMountPath    string // default "approle"
}

type KeyManager struct {
	client    *vaultapi.Client
	mountPath string

	cfg    Config
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

var (
	_ keymanager.KeyManager = (*KeyManager)(nil)
	_ keymanager.Encrypter  = (*KeyManager)(nil)
	_ keymanager.DigestSigner = (*KeyManager)(nil)
)

// New connects to Vault. With AppRole configured it logs in right away (an
// error is returned if that fails) and keeps the token alive in the
// background until Close.
func New(cfg Config) (*KeyManager, error) {
	vc := vaultapi.DefaultConfig()
	vc.Address = cfg.Address
	client, err := vaultapi.NewClient(vc)
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: creating client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	mount := cfg.MountPath
	if mount == "" {
		mount = "transit"
	}
	k := &KeyManager{client: client, mountPath: strings.Trim(mount, "/"), cfg: cfg}

	if cfg.AppRoleID == "" {
		client.SetToken(cfg.Token)
		return k, nil
	}
	if cfg.AppRoleSecretID == "" && cfg.AppRoleSecretIDFile == "" {
		return nil, fmt.Errorf("vault keymanager: AppRole needs a secret id (or a secret id file)")
	}
	secret, err := k.appRoleLogin(context.Background())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	k.cancel = cancel
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		k.keepAlive(ctx, secret)
	}()
	return k, nil
}

// Close stops the background token renewal.
func (k *KeyManager) Close() {
	if k.cancel != nil {
		k.cancel()
		k.wg.Wait()
	}
}

func (k *KeyManager) appRoleLogin(ctx context.Context) (*vaultapi.Secret, error) {
	secretID := k.cfg.AppRoleSecretID
	if k.cfg.AppRoleSecretIDFile != "" {
		raw, err := os.ReadFile(k.cfg.AppRoleSecretIDFile)
		if err != nil {
			return nil, fmt.Errorf("vault keymanager: reading AppRole secret id file: %w", err)
		}
		secretID = strings.TrimSpace(string(raw))
	}
	mount := strings.Trim(k.cfg.AppRoleMountPath, "/")
	if mount == "" {
		mount = "approle"
	}
	secret, err := k.client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]interface{}{
		"role_id":   k.cfg.AppRoleID,
		"secret_id": secretID,
	})
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: AppRole login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault keymanager: AppRole login: no token in response")
	}
	k.client.SetToken(secret.Auth.ClientToken)
	return secret, nil
}

// keepAlive renews the token with a LifetimeWatcher when it is renewable,
// and logs in again when it can no longer be renewed (or never could be).
func (k *KeyManager) keepAlive(ctx context.Context, secret *vaultapi.Secret) {
	backoff := time.Second
	for {
		k.holdToken(ctx, secret)
		for {
			if ctx.Err() != nil {
				return
			}
			var err error
			secret, err = k.appRoleLogin(ctx)
			if err == nil {
				backoff = time.Second
				break
			}
			log.Printf("vault keymanager: %v (retrying in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}
}

// holdToken returns when the token must be replaced.
func (k *KeyManager) holdToken(ctx context.Context, secret *vaultapi.Secret) {
	if secret.Auth.Renewable {
		w, err := k.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{Secret: secret})
		if err == nil {
			go w.Start()
			defer w.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-w.DoneCh():
					return
				case <-w.RenewCh():
				}
			}
		}
	}
	// Not renewable: log in again at two thirds of the lease.
	wait := time.Duration(secret.Auth.LeaseDuration) * time.Second * 2 / 3
	if wait <= 0 {
		wait = time.Minute
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
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

var _ keymanager.KeyRemover = (*KeyManager)(nil)

// DeleteKey removes a transit key. Vault refuses until deletion_allowed is set.
func (k *KeyManager) DeleteKey(ctx context.Context, kmsKeyReference string) error {
	// POST /transit/keys/:name/config
	if _, err := k.client.Logical().WriteWithContext(ctx, k.path("keys", kmsKeyReference)+"/config", map[string]interface{}{
		"deletion_allowed": true,
	}); err != nil {
		return fmt.Errorf("vault keymanager: allow key deletion: %w", err)
	}
	// DELETE /transit/keys/:name
	if _, err := k.client.Logical().DeleteWithContext(ctx, k.path("keys", kmsKeyReference)); err != nil {
		return fmt.Errorf("vault keymanager: delete key: %w", err)
	}
	return nil
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
	if secret == nil {
		return nil, fmt.Errorf("vault keymanager: sign: empty response")
	}
	raw, _ := secret.Data["signature"].(string)
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault keymanager: unexpected signature format %q", raw)
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

func (k *KeyManager) SignDigest(ctx context.Context, kmsKeyReference string, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("vault keymanager: digest must be %d bytes (SHA-256), got %d", sha256.Size, len(digest))
	}
	secret, err := k.client.Logical().WriteWithContext(ctx, k.path("sign", kmsKeyReference), map[string]interface{}{
		"input":               base64.StdEncoding.EncodeToString(digest),
		"prehashed":           true,
		"hash_algorithm":      "sha2-256",
		"signature_algorithm": "pkcs1v15",
	})
	if err != nil {
		return nil, fmt.Errorf("vault keymanager: sign digest: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("vault keymanager: sign digest: empty response")
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
