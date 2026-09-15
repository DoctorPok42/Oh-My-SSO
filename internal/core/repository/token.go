package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type TokenRepository interface {
	Create(ctx context.Context, p CreateTokenParams) (*domain.Token, error)
	GetByID(ctx context.Context, id string) (*domain.Token, error)
	GetByJTI(ctx context.Context, jti string) (*domain.Token, error)
	ListBySession(ctx context.Context, sessionID string) ([]*domain.Token, error)
	Revoke(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateTokenParams struct {
	SessionID   string
	ClientRefID string
	Type        domain.TokenType
	JTI         string
	ExpiresAt   time.Time
	Scopes      []string
}
