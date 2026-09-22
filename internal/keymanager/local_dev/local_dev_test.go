package localdev_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
)

func TestLocalDev_GenerateAndSign(t *testing.T) {
	tests := []struct {
		name    string
		keyType keymanager.KeyType
	}{
		{name: "RSA", keyType: keymanager.KeyTypeRSA},
		{name: "EC", keyType: keymanager.KeyTypeEC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := localdev.New("test")
			ctx := context.Background()

			generated, err := km.GenerateKey(ctx, tt.keyType)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if generated.KMSKeyReference == "" {
				t.Fatal("expected a non-empty KMSKeyReference")
			}

			payload := []byte("hello from oh-my-sso")
			sig, err := km.Sign(ctx, generated.KMSKeyReference, payload)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			verifySignature(t, tt.keyType, generated.PublicKeyPEM, payload, sig)
		})
	}
}

func TestLocalDev_ProductionGuard(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected New(\"production\") to panic, it did not")
		}
	}()
	localdev.New("production")
}

func TestLocalDev_UnknownKeyReference(t *testing.T) {
	km := localdev.New("test")
	_, err := km.Sign(context.Background(), "does-not-exist", []byte("payload"))
	if err == nil {
		t.Fatal("expected an error signing with an unknown key reference, got nil")
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
