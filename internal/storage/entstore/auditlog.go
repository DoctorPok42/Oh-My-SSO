package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/auditlog"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entAuditLogRepository struct {
	client *ent.Client
}

func NewAuditLogRepository(client *ent.Client) repository.AuditLogRepository {
	return &entAuditLogRepository{client: client}
}

func (r *entAuditLogRepository) Create(ctx context.Context, p repository.CreateAuditLogParams) (*domain.AuditLog, error) {
	builder := r.client.AuditLog.
		Create().
		SetRealmID(p.RealmID).
		SetNillableUserID(nonEmpty(p.UserID)).
		SetAction(p.Action).
		SetNillableResourceType(nonEmpty(p.ResourceType)).
		SetNillableResourceID(nonEmpty(p.ResourceID)).
		SetNillableIPAddress(nonEmpty(p.IPAddress)).
		SetNillableUserAgent(nonEmpty(p.UserAgent)).
		SetLevel(entschema.AuditLogLevel(p.Level)).
		SetStatus(entschema.AuditLogStatus(p.Status))
	if p.Details != nil {
		builder = builder.SetDetails(p.Details)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainAuditLog(e), nil
}

func (r *entAuditLogRepository) GetByID(ctx context.Context, id string) (*domain.AuditLog, error) {
	e, err := r.client.AuditLog.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainAuditLog(e), nil
}

func (r *entAuditLogRepository) ListByResource(ctx context.Context, resourceType, resourceID string) ([]*domain.AuditLog, error) {
	rows, err := r.client.AuditLog.
		Query().
		Where(auditlog.ResourceType(resourceType), auditlog.ResourceID(resourceID)).
		Order(ent.Desc(auditlog.FieldTimestamp)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainAuditLogs(rows), nil
}

func (r *entAuditLogRepository) ListByUser(ctx context.Context, userID string) ([]*domain.AuditLog, error) {
	rows, err := r.client.AuditLog.
		Query().
		Where(auditlog.UserID(userID)).
		Order(ent.Desc(auditlog.FieldTimestamp)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainAuditLogs(rows), nil
}

func (r *entAuditLogRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.AuditLog, error) {
	rows, err := r.client.AuditLog.
		Query().
		Where(auditlog.RealmID(realmID)).
		Order(ent.Desc(auditlog.FieldTimestamp)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainAuditLogs(rows), nil
}

func toDomainAuditLogs(rows []*ent.AuditLog) []*domain.AuditLog {
	out := make([]*domain.AuditLog, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainAuditLog(e))
	}
	return out
}

func toDomainAuditLog(e *ent.AuditLog) *domain.AuditLog {
	return &domain.AuditLog{
		ID:           e.ID,
		RealmID:      e.RealmID,
		UserID:       e.UserID,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Timestamp:    e.Timestamp,
		IPAddress:    e.IPAddress,
		UserAgent:    e.UserAgent,
		Level:        domain.AuditLogLevel(e.Level),
		Status:       domain.AuditLogStatus(e.Status),
		Details:      e.Details,
	}
}
