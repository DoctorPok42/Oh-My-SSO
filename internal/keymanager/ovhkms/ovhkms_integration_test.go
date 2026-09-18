package ovhkms_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/google/uuid"

	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/keymanager/ovhkms"
)

func TestOVHKMSIntegration_GenerateAndSign(t *testing.T) {
	endpoint := os.Getenv("OVHKMS_ENDPOINT")
	domainID := os.Getenv("OVHKMS_DOMAIN_ID")
	certFile := os.Getenv("OVHKMS_CLIENT_CERT_FILE")
	keyFile := os.Getenv("OVHKMS_CLIENT_KEY_FILE")

	if endpoint == "" || domainID == "" || certFile == "" || keyFile == "" {
		t.Skip("OVHKMS_* not set — skipping OVH KMS integration test")
	}

	okmsID, err := uuid.Parse(domainID)
	if err != nil {
		t.Fatalf("invalid OVHKMS_DOMAIN_ID: %v", err)
	}

	km, err := ovhkms.New(ovhkms.Config{
		Endpoint:       endpoint,
		OkmsID:         okmsID,
		ClientCertFile: certFile,
		ClientKeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("ovhkms.New: %v", err)
	}

	ctx := context.Background()

	generated, err := km.GenerateKey(ctx, keymanager.KeyTypeRSA)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Logf("key created on OVH KMS — kms_key_reference=%s", generated.KMSKeyReference)
	t.Logf("public key:\n%s", generated.PublicKeyPEM)

	payload := []byte("hello from oh-my-sso")
	sig, err := km.Sign(ctx, generated.KMSKeyReference, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	block, _ := pem.Decode([]byte(generated.PublicKeyPEM))
	if block == nil {
		t.Fatal("failed to decode public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}

	hash := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	t.Log("generate, sign and verify all succeeded against the real OVH KMS")
}
