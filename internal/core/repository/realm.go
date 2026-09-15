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
