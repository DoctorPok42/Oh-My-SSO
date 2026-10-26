package adminapi

import (
	"testing"
	"time"

	"sso.internal/sso/internal/core/domain"
)

func TestToKeyViewAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		keyType domain.SigningKeyType
		want    string
	}{
		{domain.SigningKeyRSA, "RS256"},
		{domain.SigningKeyEC, "ES256"},
		{domain.SigningKeyAES, "A256GCM"}, // envelope encryption, not a signature
	} {
		v := toKeyView(&domain.SigningKey{Kid: "k", KeyType: tc.keyType, KMSKeyReference: "secret-ref", CreatedAt: time.Now()})
		if v.Algorithm != tc.want {
			t.Errorf("%s: algorithm %q, want %q", tc.keyType, v.Algorithm, tc.want)
		}
	}
}
