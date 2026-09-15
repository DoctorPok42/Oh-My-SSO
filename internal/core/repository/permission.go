package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type PermissionRepository interface {
	Create(ctx context.Context, p CreatePermissionParams) (*domain.Permission, error)
	GetByID(ctx context.Context, id string) (*domain.Permission, error)
	GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.Permission, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.Permission, error)
	Update(ctx context.Context, id string, p UpdatePermissionParams) (*domain.Permission, error)
	Delete(ctx context.Context, id string) error
}

type CreatePermissionParams struct {
	RealmID     string
	Name        string
	Description string
	Resource    string
	Action      string
	Scope       string
	Constraints map[string]interface{}
}

type UpdatePermissionParams struct {
	Name        *string
	Description *string
	Status      *domain.PermissionStatus
	Resource    *string
	Action      *string
	Scope       *string
	Constraints map[string]interface{}
}
