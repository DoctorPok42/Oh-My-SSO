package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type MfaBackupCodeRepository interface {
	Create(ctx context.Context, p CreateMfaBackupCodeParams) (*domain.MfaBackupCode, error)
	GetByID(ctx context.Context, id string) (*domain.MfaBackupCode, error)
	ListByUser(ctx context.Context, userID string) ([]*domain.MfaBackupCode, error)
	ListByBatch(ctx context.Context, userID, batchID string) ([]*domain.MfaBackupCode, error)
	GetByCodeHash(ctx context.Context, codeHash string) (*domain.MfaBackupCode, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteByBatch(ctx context.Context, userID, batchID string) error
	Delete(ctx context.Context, id string) error
}

type CreateMfaBackupCodeParams struct {
	UserID   string
	BatchID  string
	CodeHash string
}
