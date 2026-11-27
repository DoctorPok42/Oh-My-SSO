package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

// ApiResourceRepository: the APIs of a realm (RFC 8707), loaded with their
// scopes.
type ApiResourceRepository interface {
	Create(ctx context.Context, p CreateApiResourceParams) (*domain.ApiResource, error)
	GetByID(ctx context.Context, id string) (*domain.ApiResource, error)
	GetByRealmAndIdentifier(ctx context.Context, realmID, identifier string) (*domain.ApiResource, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.ApiResource, error)
	Update(ctx context.Context, id string, p UpdateApiResourceParams) (*domain.ApiResource, error)
	Delete(ctx context.Context, id string) error
}

type CreateApiResourceParams struct {
	RealmID     string
	Identifier  string
	Name        string
	Description string
	ScopeIDs    []string
}

type UpdateApiResourceParams struct {
	Name        *string
	Description *string
	ScopeIDs    []string // nil: unchanged
}
