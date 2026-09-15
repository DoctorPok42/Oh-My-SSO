package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type PasswordResetTokenRepository interface {
	Create(ctx context.Context, p CreatePasswordResetTokenParams) (*domain.PasswordResetToken, error)
	GetByID(ctx context.Context, id string) (*domain.PasswordResetToken, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error)
	MarkUsed(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreatePasswordResetTokenParams struct {
	UserID      string
	TokenHash   string
	ExpiresAt   time.Time
	RequestedIP string
}
