package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type SigningKeyRepository interface {
	Create(ctx context.Context, p CreateSigningKeyParams) (*domain.SigningKey, error)
	GetByID(ctx context.Context, id string) (*domain.SigningKey, error)
	GetByKid(ctx context.Context, kid string) (*domain.SigningKey, error)
	ListActiveByRealm(ctx context.Context, realmID string) ([]*domain.SigningKey, error)
	SetStatus(ctx context.Context, id string, status domain.SigningKeyStatus) error
	Retire(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateSigningKeyParams struct {
	RealmID         string
	KeyType         domain.SigningKeyType
	Purpose         domain.SigningKeyPurpose
	KMSKeyReference string
	KMSBackend      string
	PublicKey       string
	Kid             string
}
