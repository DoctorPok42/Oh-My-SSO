package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type KeyRotationLogRepository interface {
	Create(ctx context.Context, p CreateKeyRotationLogParams) (*domain.KeyRotationLog, error)
	GetByID(ctx context.Context, id string) (*domain.KeyRotationLog, error)
	ListBySigningKey(ctx context.Context, signingKeyID string) ([]*domain.KeyRotationLog, error)
}

type CreateKeyRotationLogParams struct {
	SigningKeyID string
	Action       domain.KeyRotationAction
	TriggeredBy  string
	Reason       string
}
