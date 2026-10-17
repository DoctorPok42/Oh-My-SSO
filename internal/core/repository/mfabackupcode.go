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

	// ReplaceForUser deletes every code of the user and creates the new
	// batch, in one transaction: the old batch stops working at the exact
	// moment the new one exists.
	ReplaceForUser(ctx context.Context, userID, batchID string, codeHashes []string) error

	// ListUnusedByUser returns the codes of the user that were not used yet.
	ListUnusedByUser(ctx context.Context, userID string) ([]*domain.MfaBackupCode, error)

	// ConsumeIfUnused marks the code used only if it was still unused, and
	// tells whether this call did it. Two requests with the same code at
	// the same time: exactly one gets true.
	ConsumeIfUnused(ctx context.Context, id string) (bool, error)

	// DeleteByUser removes every code of the user.
	DeleteByUser(ctx context.Context, userID string) (int, error)
}

type CreateMfaBackupCodeParams struct {
	UserID   string
	BatchID  string
	CodeHash string
}
