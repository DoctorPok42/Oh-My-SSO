package localdev_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
)

// Step 11: SignDigest signs a digest computed by the caller (XML-DSig,
// X.509). The result must verify exactly like Sign over the payload.
func TestLocalDev_SignDigest(t *testing.T) {
	ctx := context.Background()
	km := localdev.New("test")
	var _ keymanager.DigestSigner = km

	for _, kt := range []keymanager.KeyType{keymanager.KeyTypeRSA, keymanager.KeyTypeEC} {
		t.Run(string(kt), func(t *testing.T) {
			generated, err := km.GenerateKey(ctx, kt)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("<ds:SignedInfo>...</ds:SignedInfo>")
			digest := sha256.Sum256(payload)
			sig, err := km.SignDigest(ctx, generated.KMSKeyReference, digest[:])
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}
			verifySignature(t, kt, generated.PublicKeyPEM, payload, sig)

			if kt == keymanager.KeyTypeRSA {
				// PKCS#1 v1.5 is deterministic: same bytes as Sign(payload).
				full, err := km.Sign(ctx, generated.KMSKeyReference, payload)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(full, sig) {
					t.Fatal("SignDigest(sha256(p)) and Sign(p) differ")
				}
			}
		})
	}

	t.Run("refused", func(t *testing.T) {
		generated, _ := km.GenerateKey(ctx, keymanager.KeyTypeRSA)
		if _, err := km.SignDigest(ctx, generated.KMSKeyReference, []byte("not 32 bytes")); err == nil {
			t.Fatal("a digest that is not SHA-256 sized must be refused")
		}
		d := sha256.Sum256(nil)
		if _, err := km.SignDigest(ctx, "unknown", d[:]); err == nil {
			t.Fatal("unknown key reference must fail")
		}
	})
}
