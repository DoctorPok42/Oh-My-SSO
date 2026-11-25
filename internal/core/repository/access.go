package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type AccessRepository interface {
	GetUserAccess(ctx context.Context, userID string) (*domain.UserAccess, error)
	GetClientAccessPolicy(ctx context.Context, clientRef string) (*domain.ClientAccessPolicy, error)
	// GetServiceRoles: the roles of the client's own service account
	// (client_credentials grant), with their permissions and client scopes.
	// Kept out of GetClientAccessPolicy, which every user sign-in reads.
	GetServiceRoles(ctx context.Context, clientRef string) ([]domain.AccessSource, error)
}
