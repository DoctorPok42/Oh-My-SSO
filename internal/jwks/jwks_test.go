package jwks_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/jwks"
)

func pemOf(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func key(kid string, kt domain.SigningKeyType, pemStr string) *domain.SigningKey {
	return &domain.SigningKey{Kid: kid, KeyType: kt, Purpose: domain.SigningKeyPurposeJWT, PublicKey: pemStr}
}

func TestFromSigningKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk, err := jwks.FromSigningKey(key("kid-rsa", domain.SigningKeyRSA, pemOf(t, &priv.PublicKey)))
	require.NoError(t, err)

	require.Equal(t, "RSA", jwk.Kty)
	require.Equal(t, "kid-rsa", jwk.Kid)
	require.Equal(t, "sig", jwk.Use)
	require.Equal(t, "RS256", jwk.Alg)
	require.Equal(t, "AQAB", jwk.E, "65537 in base64url, the value every JWKS shows")
	require.Empty(t, jwk.Crv+jwk.X+jwk.Y, "no EC field on an RSA key")

	// A client rebuilds exactly the same public key from the JSON.
	pub, err := jwk.PublicKey()
	require.NoError(t, err)
	require.True(t, priv.PublicKey.Equal(pub))
}

func TestFromSigningKey_ECKeepsLeadingZeros(t *testing.T) {
	// RFC 7518 §6.2.1.2: x and y MUST be the full coordinate size (32 bytes
	// for P-256), even when they start with 0x00. A naive big.Int.Bytes()
	// encoding drops that byte (~1 key in 128): generate keys until we hit
	// such a case, so the test really covers it.
	var priv *ecdsa.PrivateKey
	for i := 0; i < 5000; i++ {
		p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		raw, err := p.PublicKey.Bytes()
		require.NoError(t, err)
		if raw[1] == 0 || raw[33] == 0 { // first byte of X or of Y
			priv = p
			break
		}
	}
	require.NotNil(t, priv, "no key with a leading zero found (statistically ~impossible)")

	jwk, err := jwks.FromSigningKey(key("kid-ec", domain.SigningKeyEC, pemOf(t, &priv.PublicKey)))
	require.NoError(t, err)

	require.Equal(t, "EC", jwk.Kty)
	require.Equal(t, "ES256", jwk.Alg)
	require.Equal(t, "P-256", jwk.Crv)
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	require.Len(t, x, 32)
	require.Len(t, y, 32)
	require.Empty(t, jwk.N+jwk.E, "no RSA field on an EC key")

	pub, err := jwk.PublicKey()
	require.NoError(t, err)
	require.True(t, priv.PublicKey.Equal(pub))
}

func TestFromSigningKey_Rejects(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	notAPublicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))

	tests := []struct {
		name string
		key  *domain.SigningKey
		want error
	}{
		{"empty public key", key("k", domain.SigningKeyRSA, ""), jwks.ErrNoPublicKey},
		{"not PEM", key("k", domain.SigningKeyRSA, "hello"), jwks.ErrInvalidPEM},
		{"PEM of another type", key("k", domain.SigningKeyRSA, notAPublicKey), jwks.ErrInvalidPEM},
		{"RSA below 2048 bits", key("k", domain.SigningKeyRSA, pemOf(t, &rsa1024.PublicKey)), jwks.ErrUnsupportedKey},
		{"EC curve other than P-256", key("k", domain.SigningKeyEC, pemOf(t, &p384.PublicKey)), jwks.ErrUnsupportedKey},
		{"Ed25519", key("k", domain.SigningKeyRSA, pemOf(t, edPub)), jwks.ErrUnsupportedKey},
		{"RSA PEM stored as EC", key("k", domain.SigningKeyEC, pemOf(t, &rsa2048.PublicKey)), jwks.ErrKeyTypeMismatch},
		{"unknown key type", key("k", "DSA", pemOf(t, &rsa2048.PublicKey)), jwks.ErrUnsupportedKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := jwks.FromSigningKey(tt.key)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestFromSigningKeys_SkipsBrokenKeysAndKeepsOrder(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	set, skipped := jwks.FromSigningKeys([]*domain.SigningKey{
		key("first", domain.SigningKeyRSA, pemOf(t, &a.PublicKey)),
		key("broken", domain.SigningKeyRSA, "garbage"),
		key("second", domain.SigningKeyEC, pemOf(t, &b.PublicKey)),
	})

	require.Len(t, set.Keys, 2)
	require.Equal(t, "first", set.Keys[0].Kid)
	require.Equal(t, "second", set.Keys[1].Kid)
	require.Len(t, skipped, 1)
	require.Equal(t, "broken", skipped[0].Kid)

	_, ok := set.Find("second")
	require.True(t, ok)
	_, ok = set.Find("broken")
	require.False(t, ok)
}

func TestSetJSON(t *testing.T) {
	t.Run("empty set is an empty array, not null", func(t *testing.T) {
		set, _ := jwks.FromSigningKeys(nil)
		b, err := json.Marshal(set)
		require.NoError(t, err)
		require.JSONEq(t, `{"keys":[]}`, string(b))
	})

	t.Run("RSA key has exactly the public members", func(t *testing.T) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		set, _ := jwks.FromSigningKeys([]*domain.SigningKey{key("k1", domain.SigningKeyRSA, pemOf(t, &priv.PublicKey))})
		b, err := json.Marshal(set)
		require.NoError(t, err)

		var raw struct {
			Keys []map[string]any `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(b, &raw))
		require.Len(t, raw.Keys, 1)
		members := make([]string, 0)
		for m := range raw.Keys[0] {
			members = append(members, m)
		}
		require.ElementsMatch(t, []string{"kty", "kid", "use", "alg", "n", "e"}, members,
			"never a private member such as d, p, q")
	})
}

func TestJWKPublicKey_Rejects(t *testing.T) {
	tests := []struct {
		name string
		jwk  jwks.JWK
	}{
		{"unknown kty", jwks.JWK{Kty: "oct"}},
		{"bad base64", jwks.JWK{Kty: "RSA", N: "!!!", E: "AQAB"}},
		{"EC other curve", jwks.JWK{Kty: "EC", Crv: "P-384"}},
		{"EC short coordinate", jwks.JWK{Kty: "EC", Crv: "P-256", X: "AQ", Y: "AQ"}},
		{"EC point not on curve", jwks.JWK{Kty: "EC", Crv: "P-256",
			X: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.PublicKey()
			require.Error(t, err)
		})
	}
}

func TestAlgorithm(t *testing.T) {
	alg, err := jwks.Algorithm(domain.SigningKeyRSA)
	require.NoError(t, err)
	require.Equal(t, "RS256", alg)
	alg, err = jwks.Algorithm(domain.SigningKeyEC)
	require.NoError(t, err)
	require.Equal(t, "ES256", alg)
	_, err = jwks.Algorithm("HS256")
	require.ErrorIs(t, err, jwks.ErrUnsupportedKey)
}
