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

// CreateAuditLogParams is one entry to write. UserID is the actor (who did
// it), TargetUserID the user it is about: an administrator unlocking alice
// is UserID=<admin>, ActorType=admin, TargetUserID=<alice>; the lockout
// locking alice is UserID="", ActorType=system, TargetUserID=<alice>.
type CreateAuditLogParams struct {
	RealmID      string
	UserID       string
	ActorType    domain.AuditActorType // empty: user when UserID is set, system otherwise
	TargetUserID string                // empty: ResourceID when ResourceType is "User", else UserID for a user actor
	Action       string
	ResourceType string
	ResourceID   string
	IPAddress    string
	UserAgent    string
	Level        domain.AuditLogLevel
	Status       domain.AuditLogStatus
	Details      map[string]interface{}
}

// Normalized fills the defaults documented on the fields.
func (p CreateAuditLogParams) Normalized() CreateAuditLogParams {
	if p.ActorType == "" {
		if p.UserID != "" {
			p.ActorType = domain.AuditActorUser
		} else {
			p.ActorType = domain.AuditActorSystem
		}
	}
	if p.TargetUserID == "" && p.ResourceType == "User" {
		p.TargetUserID = p.ResourceID
	}
	if p.TargetUserID == "" && p.ActorType == domain.AuditActorUser {
		p.TargetUserID = p.UserID // a user acting on their own account
	}
	if p.Level == "" {
		p.Level = domain.AuditLogInfo
	}
	if p.Status == "" {
		p.Status = domain.AuditLogSuccess
	}
	return p
}
