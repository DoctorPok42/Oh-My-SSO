package service_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

func rsaBitsOfKey(t *testing.T, k *domain.SigningKey) int {
	t.Helper()
	block, _ := pem.Decode([]byte(k.PublicKey))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return pub.(*rsa.PublicKey).N.BitLen()
}

func TestRotate_RSAKeySize(t *testing.T) {
	ctx := context.Background()

	t.Run("default 2048, then the requested size, then kept when not asked", func(t *testing.T) {
		f := newRotFixture(t)
		require.Equal(t, 2048, rsaBitsOfKey(t, f.rotate(t, service.RotateInput{}).NewKey))
		require.Equal(t, 3072, rsaBitsOfKey(t, f.rotate(t, service.RotateInput{RSABits: 3072}).NewKey))
		require.Equal(t, 3072, rsaBitsOfKey(t, f.rotate(t, service.RotateInput{}).NewKey), "the realm keeps its size")
		require.Equal(t, 2048, rsaBitsOfKey(t, f.rotate(t, service.RotateInput{RSABits: 2048}).NewKey), "and can go back")
	})

	t.Run("an unsupported size is refused before anything is created", func(t *testing.T) {
		f := newRotFixture(t)
		_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, RSABits: 1024})
		require.ErrorIs(t, err, service.ErrInvalidRSABits)
		keys, err := f.rot.List(ctx, rotRealm)
		require.NoError(t, err)
		require.Empty(t, keys)
	})

	t.Run("a size with an EC key is refused", func(t *testing.T) {
		f := newRotFixture(t)
		_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, KeyType: domain.SigningKeyEC, RSABits: 3072})
		require.ErrorIs(t, err, service.ErrRSABitsNeedsRSA)

		// Same when the type is the current key's (EC).
		f.rotate(t, service.RotateInput{KeyType: domain.SigningKeyEC})
		_, err = f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, RSABits: 3072})
		require.ErrorIs(t, err, service.ErrRSABitsNeedsRSA)
	})

	t.Run("automatic rotation keeps the size", func(t *testing.T) {
		f := newRotFixtureOn(t, "vault") // RotateDue refuses local_dev
		f.settings.intervalDays = 30
		f.rotate(t, service.RotateInput{RSABits: 3072})
		f.advance(31 * 24 * time.Hour)

		rotated, err := f.rot.RotateDue(ctx, rotRealm)
		require.NoError(t, err)
		require.True(t, rotated)

		keys, err := f.rot.List(ctx, rotRealm)
		require.NoError(t, err)
		require.Len(t, keys, 2)
		require.Equal(t, 3072, rsaBitsOfKey(t, keys[0]), "newest first")
	})
}
