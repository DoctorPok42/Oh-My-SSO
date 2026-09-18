package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/keymanager"
)

type GenerateSigningKeyParams struct {
	RealmID string
	KeyType domain.SigningKeyType
	Purpose domain.SigningKeyPurpose
}

func GenerateSigningKey(
	ctx context.Context,
	km keymanager.KeyManager,
	repo repository.SigningKeyRepository,
	kmsBackend string, // "vault", "local_dev", "ovhkms"
	params GenerateSigningKeyParams,
) (*domain.SigningKey, error) {
	kmType, err := toKeyManagerType(params.KeyType)
	if err != nil {
		return nil, err
	}

	generated, err := km.GenerateKey(ctx, kmType)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	return repo.Create(ctx, repository.CreateSigningKeyParams{
		RealmID:         params.RealmID,
		KeyType:         params.KeyType,
		Purpose:         params.Purpose,
		KMSKeyReference: generated.KMSKeyReference,
		KMSBackend:      kmsBackend,
		PublicKey:       generated.PublicKeyPEM,
		Kid:             uuid.NewString(),
	})
}

func toKeyManagerType(t domain.SigningKeyType) (keymanager.KeyType, error) {
	switch t {
	case domain.SigningKeyRSA:
		return keymanager.KeyTypeRSA, nil
	case domain.SigningKeyEC:
		return keymanager.KeyTypeEC, nil
	default:
		return "", fmt.Errorf("unsupported signing key type %q", t)
	}
}
