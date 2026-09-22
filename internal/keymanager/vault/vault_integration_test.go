package vault_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/keymanager/vault"
)

func TestVaultIntegration_GenerateAndSign(t *testing.T) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("VAULT_ADDR / VAULT_TOKEN not set — skipping Vault integration test")
	}

	km, err := vault.New(vault.Config{Address: addr, Token: token})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	tests := []struct {
		name    string
		keyType keymanager.KeyType
	}{
		{name: "RSA", keyType: keymanager.KeyTypeRSA},
		{name: "EC", keyType: keymanager.KeyTypeEC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			generated, err := km.GenerateKey(ctx, tt.keyType)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			t.Logf("key created in Vault Transit — kms_key_reference=%s", generated.KMSKeyReference)

			payload := []byte("hello from oh-my-sso")
			sig, err := km.Sign(ctx, generated.KMSKeyReference, payload)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			verifySignature(t, tt.keyType, generated.PublicKeyPEM, payload, sig)
		})
	}
}

func verifySignature(t *testing.T, keyType keymanager.KeyType, publicKeyPEM string, payload, sig []byte) {
	t.Helper()

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		t.Fatal("failed to decode public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	hash := sha256.Sum256(payload)

	switch keyType {
	case keymanager.KeyTypeRSA:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("expected *rsa.PublicKey, got %T", pub)
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
	case keymanager.KeyTypeEC:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
		}
		if !ecdsa.VerifyASN1(ecPub, hash[:], sig) {
			t.Fatal("signature does not verify")
		}
	default:
		t.Fatalf("unhandled key type %q in test helper", keyType)
	}
}
