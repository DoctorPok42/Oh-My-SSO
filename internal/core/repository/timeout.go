package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type TimeoutRepository interface {
	Create(ctx context.Context, p CreateTimeoutParams) (*domain.Timeout, error)
	GetByID(ctx context.Context, id string) (*domain.Timeout, error)
	ListActiveForTarget(ctx context.Context, targetType domain.TimeoutTargetType, targetID string) ([]*domain.Timeout, error)
	Update(ctx context.Context, id string, p UpdateTimeoutParams) (*domain.Timeout, error)
	Lift(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateTimeoutParams struct {
	RealmID    string
	TargetType domain.TimeoutTargetType
	TargetID   string
	StartsAt   time.Time
	EndsAt     time.Time
	Reason     string
	CreatedBy  string
}

type UpdateTimeoutParams struct {
	Reason *string
	EndsAt *time.Time
}
