package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type MfaMethodRepository interface {
	Create(ctx context.Context, p CreateMfaMethodParams) (*domain.MfaMethod, error)
	GetByID(ctx context.Context, id string) (*domain.MfaMethod, error)
	ListByUser(ctx context.Context, userID string) ([]*domain.MfaMethod, error)
	Update(ctx context.Context, id string, p UpdateMfaMethodParams) (*domain.MfaMethod, error)
	MarkUsed(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateMfaMethodParams struct {
	UserID          string
	Type            domain.MfaMethodType
	SecretEncrypted string
	CredentialID    string
	PublicKey       string
	IsDiscoverable  bool
}

type UpdateMfaMethodParams struct {
	Status *domain.MfaMethodStatus
}
