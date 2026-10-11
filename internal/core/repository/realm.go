package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type RealmRepository interface {
	Create(ctx context.Context, p CreateRealmParams) (*domain.Realm, error)
	GetByID(ctx context.Context, id string) (*domain.Realm, error)
	GetByName(ctx context.Context, name string) (*domain.Realm, error)
	Update(ctx context.Context, id string, p UpdateRealmParams) (*domain.Realm, error)
	Delete(ctx context.Context, id string) error

	// EnsurePairwiseSubjectSalt stores candidate as the realm's pairwise
	// subject salt if none is set yet, then returns the salt actually stored.
	// It is atomic: concurrent callers all get the same, first-written value.
	EnsurePairwiseSubjectSalt(ctx context.Context, realmID, candidate string) (string, error)
}

type CreateRealmParams struct {
	Name        string
	DisplayName string
}

type UpdateRealmParams struct {
	Name        *string
	DisplayName *string
	Status      *domain.RealmStatus
}
