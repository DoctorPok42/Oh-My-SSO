package localdev_test

import (
	"bytes"
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

func TestEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	km := localdev.New("test")

	ref, err := km.GenerateEncryptionKey(ctx)
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	ct, err := km.Encrypt(ctx, ref, []byte("data key"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, []byte("data key")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	pt, err := km.Decrypt(ctx, ref, ct)
	if err != nil || string(pt) != "data key" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}

	other, _ := km.GenerateEncryptionKey(ctx)
	if _, err := km.Decrypt(ctx, other, ct); err == nil {
		t.Fatal("decrypting with another key must fail")
	}
	ct[len(ct)-1] ^= 1
	if _, err := km.Decrypt(ctx, ref, ct); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestEnvelopeMasterKeySurvivesRestart(t *testing.T) {
	ctx := context.Background()
	master := bytes.Repeat([]byte{7}, 32)

	first := localdev.New("test", localdev.WithEnvelopeMasterKey(master))
	ref, _ := first.GenerateEncryptionKey(ctx)
	ct, err := first.Encrypt(ctx, ref, []byte("totp secret"))
	if err != nil {
		t.Fatal(err)
	}

	restarted := localdev.New("test", localdev.WithEnvelopeMasterKey(master))
	if pt, err := restarted.Decrypt(ctx, ref, ct); err != nil || string(pt) != "totp secret" {
		t.Fatalf("same master key after restart: %q, %v", pt, err)
	}
	if _, err := localdev.New("test").Decrypt(ctx, ref, ct); err == nil {
		t.Fatal("a random master key (no LOCALDEV_ENVELOPE_KEY) cannot decrypt the previous run's data")
	}
}
