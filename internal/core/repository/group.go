package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type GroupRepository interface {
	Create(ctx context.Context, p CreateGroupParams) (*domain.Group, error)
	GetByID(ctx context.Context, id string) (*domain.Group, error)
	GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.Group, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.Group, error)
	Update(ctx context.Context, id string, p UpdateGroupParams) (*domain.Group, error)
	Delete(ctx context.Context, id string) error
}

type CreateGroupParams struct {
	RealmID     string
	Name        string
	Description string
}

type UpdateGroupParams struct {
	Name        *string
	Description *string
	Status      *domain.GroupStatus
}
