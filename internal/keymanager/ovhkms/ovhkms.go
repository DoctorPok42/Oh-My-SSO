package ovhkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	okms "github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"

	"sso.internal/sso/internal/keymanager"
)

type Config struct {
	Endpoint      string    // ex: "https://eu-west-rbx.okms.ovh.net"
	OkmsID        uuid.UUID // ID of the OKMS service (UUID)
	ClientCertFile string   // path to the access certificate (PEM)
	ClientKeyFile  string   // path to the access certificate private key (PEM)
}

type KeyManager struct {
	client *okms.Client
	okmsID uuid.UUID

	mu      sync.RWMutex
	signers map[string]crypto.Signer // cache of crypto.Signer by KMS key reference
}

var _ keymanager.KeyManager = (*KeyManager)(nil)

func New(cfg Config) (*KeyManager, error) {
	certFile := strings.TrimSpace(cfg.ClientCertFile)
	keyFile := strings.TrimSpace(cfg.ClientKeyFile)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("ovhkms keymanager: loading access certificate: %w", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}},
	}

	client, err := okms.NewRestAPIClientWithHttp(cfg.Endpoint, httpClient)
	if err != nil {
		return nil, fmt.Errorf("ovhkms keymanager: creating client: %w", err)
	}

	return &KeyManager{
		client:  client,
		okmsID:  cfg.OkmsID,
		signers: make(map[string]crypto.Signer),
	}, nil
}

func (k *KeyManager) GenerateKey(ctx context.Context, keyType keymanager.KeyType) (*keymanager.GeneratedKey, error) {
	ops := []types.CryptographicUsages{types.Sign, types.Verify}

	var resp *types.GetServiceKeyResponse
	var err error
	switch keyType {
	case keymanager.KeyTypeRSA:
		resp, err = k.client.GenerateRSAKeyPair(ctx, k.okmsID, types.N2048, "sso-signing-key", types.SOFTWARE, "", ops)
	case keymanager.KeyTypeEC:
		resp, err = k.client.GenerateECKeyPair(ctx, k.okmsID, types.P256, "sso-signing-key", types.SOFTWARE, "", ops)
	default:
		return nil, fmt.Errorf("ovhkms keymanager: unsupported key type %q", keyType)
	}
	if err != nil {
		return nil, fmt.Errorf("ovhkms keymanager: generate key: %w", err)
	}

	pub, err := k.client.ExportPublicKey(ctx, k.okmsID, resp.Id)
	if err != nil {
		return nil, fmt.Errorf("ovhkms keymanager: export public key: %w", err)
	}
	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		return nil, err
	}

	return &keymanager.GeneratedKey{
		KMSKeyReference: resp.Id.String(),
		PublicKeyPEM:    pubPEM,
	}, nil
}

func (k *KeyManager) Sign(ctx context.Context, kmsKeyReference string, payload []byte) ([]byte, error) {
	signer, err := k.signerFor(ctx, kmsKeyReference)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	return signer.Sign(rand.Reader, hash[:], crypto.SHA256)
}

// signerFor returns a crypto.Signer for the given KMS key reference, caching it for future use.
func (k *KeyManager) signerFor(ctx context.Context, kmsKeyReference string) (crypto.Signer, error) {
	k.mu.RLock()
	s, ok := k.signers[kmsKeyReference]
	k.mu.RUnlock()
	if ok {
		return s, nil
	}

	keyID, err := uuid.Parse(kmsKeyReference)
	if err != nil {
		return nil, fmt.Errorf("ovhkms keymanager: invalid key reference %q: %w", kmsKeyReference, err)
	}
	signer, err := k.client.NewSigner(ctx, k.okmsID, keyID)
	if err != nil {
		return nil, fmt.Errorf("ovhkms keymanager: new signer: %w", err)
	}

	k.mu.Lock()
	k.signers[kmsKeyReference] = signer
	k.mu.Unlock()
	return signer, nil
}

func encodePublicKeyPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("ovhkms keymanager: marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
