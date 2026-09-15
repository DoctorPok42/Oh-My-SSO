package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type ConsentRepository interface {
	Create(ctx context.Context, p CreateConsentParams) (*domain.Consent, error)
	GetByID(ctx context.Context, id string) (*domain.Consent, error)
	GetByUserAndClient(ctx context.Context, userID, clientRefID string) (*domain.Consent, error)
	Update(ctx context.Context, id string, p UpdateConsentParams) (*domain.Consent, error)
	Revoke(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateConsentParams struct {
	UserID      string
	ClientRefID string
	Scopes      []string
}

type UpdateConsentParams struct {
	Scopes []string
}
