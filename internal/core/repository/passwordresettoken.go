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
	// ConsumeIfUnused marks the token used and tells whether this call did
	// it. A link works exactly once, even when two requests race.
	ConsumeIfUnused(ctx context.Context, id string, at time.Time) (bool, error)
	// DeleteUnusedByUser removes the user's tokens that were never used: a
	// new request (or a successful reset) cancels the links sent before.
	DeleteUnusedByUser(ctx context.Context, userID string) (int, error)
	Delete(ctx context.Context, id string) error
}

type CreatePasswordResetTokenParams struct {
	UserID      string
	TokenHash   string
	ExpiresAt   time.Time
	RequestedIP string
}
