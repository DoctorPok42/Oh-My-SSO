package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type LoginAttemptRepository interface {
	Create(ctx context.Context, p CreateLoginAttemptParams) (*domain.LoginAttempt, error)
	GetByID(ctx context.Context, id string) (*domain.LoginAttempt, error)
	ListByIdentifier(ctx context.Context, identifier string) ([]*domain.LoginAttempt, error)
	ListByIP(ctx context.Context, ipAddress string) ([]*domain.LoginAttempt, error)
}

type CreateLoginAttemptParams struct {
	Identifier    string
	IPAddress     string
	UserAgent     string
	Status        domain.LoginAttemptStatus
	FailureReason domain.LoginAttemptFailureReason
}
