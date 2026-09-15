package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type UserRepository interface {
	Create(ctx context.Context, p CreateUserParams) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByRealmAndEmail(ctx context.Context, realmID, email string) (*domain.User, error)
	GetByRealmAndUsername(ctx context.Context, realmID, username string) (*domain.User, error)
	Update(ctx context.Context, id string, p UpdateUserParams) (*domain.User, error)
	Delete(ctx context.Context, id string) error
}

type CreateUserParams struct {
	RealmID      string
	Username     string
	Email        string
	PasswordHash string
}

type UpdateUserParams struct {
	Username     *string
	Email        *string
	PasswordHash *string
}