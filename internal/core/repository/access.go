package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type AccessRepository interface {
	GetUserAccess(ctx context.Context, userID string) (*domain.UserAccess, error)
	GetClientAccessPolicy(ctx context.Context, clientRef string) (*domain.ClientAccessPolicy, error)
}
