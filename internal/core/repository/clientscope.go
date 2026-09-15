package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type ClientScopeRepository interface {
	Create(ctx context.Context, p CreateClientScopeParams) (*domain.ClientScope, error)
	GetByID(ctx context.Context, id string) (*domain.ClientScope, error)
	GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.ClientScope, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.ClientScope, error)
	Update(ctx context.Context, id string, p UpdateClientScopeParams) (*domain.ClientScope, error)
	Delete(ctx context.Context, id string) error
}

type CreateClientScopeParams struct {
	RealmID     string
	Name        string
	Description string
}

type UpdateClientScopeParams struct {
	Name         *string
	Description  *string
	Protocol     *domain.ClientScopeProtocol
	IsDefault    *bool
	ClaimMappers []map[string]interface{}
}
