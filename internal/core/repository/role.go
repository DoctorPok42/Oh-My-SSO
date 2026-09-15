package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type RoleRepository interface {
	Create(ctx context.Context, p CreateRoleParams) (*domain.Role, error)
	GetByID(ctx context.Context, id string) (*domain.Role, error)
	GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.Role, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.Role, error)
	Update(ctx context.Context, id string, p UpdateRoleParams) (*domain.Role, error)
	Delete(ctx context.Context, id string) error
}

type CreateRoleParams struct {
	RealmID     string
	Name        string
	Description string
}

type UpdateRoleParams struct {
	Name        *string
	Description *string
	Status      *domain.RoleStatus
}
