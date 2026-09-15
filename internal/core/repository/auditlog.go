package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type AuditLogRepository interface {
	Create(ctx context.Context, p CreateAuditLogParams) (*domain.AuditLog, error)
	GetByID(ctx context.Context, id string) (*domain.AuditLog, error)
	ListByResource(ctx context.Context, resourceType, resourceID string) ([]*domain.AuditLog, error)
	ListByUser(ctx context.Context, userID string) ([]*domain.AuditLog, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.AuditLog, error)
}

type CreateAuditLogParams struct {
	RealmID      string
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	IPAddress    string
	UserAgent    string
	Level        domain.AuditLogLevel
	Status       domain.AuditLogStatus
	Details      map[string]interface{}
}
