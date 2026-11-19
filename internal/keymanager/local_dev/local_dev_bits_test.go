package localdev_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
)

func TestLocalDev_RSAKeySize(t *testing.T) {
	ctx := context.Background()
	km := localdev.New("test")

	for bits, want := range map[int]int{0: 2048, 2048: 2048, 3072: 3072} {
		generated, err := km.GenerateKey(ctx, keymanager.KeyTypeRSA, bits)
		if err != nil {
			t.Fatalf("GenerateKey(rsa, %d): %v", bits, err)
		}
		block, _ := pem.Decode([]byte(generated.PublicKeyPEM))
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if got := pub.(*rsa.PublicKey).N.BitLen(); got != want {
			t.Errorf("rsa, %d bits asked: got a %d-bit key, want %d", bits, got, want)
		}
	}

	for _, bits := range []int{1024, 2049, -1} {
		if _, err := km.GenerateKey(ctx, keymanager.KeyTypeRSA, bits); err == nil {
			t.Errorf("GenerateKey(rsa, %d) must fail", bits)
		}
	}

	// The size is for RSA only: an EC key ignores it.
	if _, err := km.GenerateKey(ctx, keymanager.KeyTypeEC, 4096); err != nil {
		t.Errorf("GenerateKey(ec, 4096): %v", err)
	}
}
