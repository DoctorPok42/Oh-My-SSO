package service_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/service"
)

func jwksOf(t *testing.T, keys ...jose.JSONWebKey) string {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	require.NoError(t, err)
	return string(b)
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return k
}

func TestNormalizeOIDCClient_PrivateKeyJWT(t *testing.T) {
	priv := rsaKey(t, 2048)
	pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "k1", Use: "sig", Algorithm: "RS256"}
	base := func(mod func(*service.OIDCClientInput)) service.OIDCClientInput {
		in := service.OIDCClientInput{ClientID: "batch", GrantTypes: []string{"client_credentials"},
			TokenEndpointAuthMethod: "private_key_jwt"}
		mod(&in)
		return in
	}

	t.Run("JWKS", func(t *testing.T) {
		got, err := service.NormalizeOIDCClient(base(func(in *service.OIDCClientInput) { in.JWKS = jwksOf(t, pub) }))
		require.NoError(t, err)
		require.Equal(t, "private_key_jwt", got.AuthMethod)
		require.Empty(t, got.JWKSURI)
		var set jose.JSONWebKeySet
		require.NoError(t, json.Unmarshal([]byte(got.JWKS), &set))
		require.Len(t, set.Keys, 1)
		require.Equal(t, "k1", set.Keys[0].KeyID)
	})

	t.Run("jwks_uri", func(t *testing.T) {
		got, err := service.NormalizeOIDCClient(base(func(in *service.OIDCClientInput) {
			in.JWKSURI = " https://batch.example.com/jwks.json "
		}))
		require.NoError(t, err)
		require.Equal(t, "https://batch.example.com/jwks.json", got.JWKSURI)
		require.Empty(t, got.JWKS)
	})

	t.Run("another method drops the keys", func(t *testing.T) {
		got, err := service.NormalizeOIDCClient(base(func(in *service.OIDCClientInput) {
			in.TokenEndpointAuthMethod = "client_secret_basic"
			in.JWKS, in.JWKSURI = jwksOf(t, pub), "https://batch.example.com/jwks.json"
		}))
		require.NoError(t, err)
		require.Empty(t, got.JWKS)
		require.Empty(t, got.JWKSURI)
	})

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other := rsaKey(t, 2048)
	refused := map[string]func(*service.OIDCClientInput){
		"no key":            func(*service.OIDCClientInput) {},
		"both":              func(in *service.OIDCClientInput) { in.JWKS, in.JWKSURI = jwksOf(t, pub), "https://k.example/jwks" },
		"http jwks_uri":     func(in *service.OIDCClientInput) { in.JWKSURI = "http://k.example/jwks" },
		"jwks_uri fragment": func(in *service.OIDCClientInput) { in.JWKSURI = "https://k.example/jwks#x" },
		"not JSON":          func(in *service.OIDCClientInput) { in.JWKS = "{" },
		"empty set":         func(in *service.OIDCClientInput) { in.JWKS = `{"keys":[]}` },
		"private key":       func(in *service.OIDCClientInput) { in.JWKS = jwksOf(t, jose.JSONWebKey{Key: priv, KeyID: "k1"}) },
		"EC key": func(in *service.OIDCClientInput) {
			in.JWKS = jwksOf(t, jose.JSONWebKey{Key: &ec.PublicKey, KeyID: "e"})
		},
		"short RSA key": func(in *service.OIDCClientInput) {
			in.JWKS = jwksOf(t, jose.JSONWebKey{Key: &rsaKey(t, 1024).PublicKey})
		},
		"encryption key": func(in *service.OIDCClientInput) {
			in.JWKS = jwksOf(t, jose.JSONWebKey{Key: &priv.PublicKey, Use: "enc"})
		},
		"two keys, one kid": func(in *service.OIDCClientInput) {
			in.JWKS = jwksOf(t, pub, jose.JSONWebKey{Key: &other.PublicKey, KeyID: "k1"})
		},
		"a secret too": func(in *service.OIDCClientInput) {
			in.JWKS, in.Secret = jwksOf(t, pub), strings.Repeat("x", 40)
		},
	}
	for name, mod := range refused {
		t.Run("refused: "+name, func(t *testing.T) {
			_, err := service.NormalizeOIDCClient(base(mod))
			require.ErrorIs(t, err, service.ErrInvalidClientConfig)
		})
	}
}
