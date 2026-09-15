package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/keyrotationlog"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entKeyRotationLogRepository struct {
	client *ent.Client
}

func NewKeyRotationLogRepository(client *ent.Client) repository.KeyRotationLogRepository {
	return &entKeyRotationLogRepository{client: client}
}

func (r *entKeyRotationLogRepository) Create(ctx context.Context, p repository.CreateKeyRotationLogParams) (*domain.KeyRotationLog, error) {
	e, err := r.client.KeyRotationLog.
		Create().
		SetSigningKeyID(p.SigningKeyID).
		SetAction(entschema.KeyRotationAction(p.Action)).
		SetTriggeredBy(p.TriggeredBy).
		SetNillableReason(nonEmpty(p.Reason)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainKeyRotationLog(e), nil
}

func (r *entKeyRotationLogRepository) GetByID(ctx context.Context, id string) (*domain.KeyRotationLog, error) {
	e, err := r.client.KeyRotationLog.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainKeyRotationLog(e), nil
}

func (r *entKeyRotationLogRepository) ListBySigningKey(ctx context.Context, signingKeyID string) ([]*domain.KeyRotationLog, error) {
	rows, err := r.client.KeyRotationLog.
		Query().
		Where(keyrotationlog.SigningKeyID(signingKeyID)).
		Order(ent.Desc(keyrotationlog.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.KeyRotationLog, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainKeyRotationLog(e))
	}
	return out, nil
}

func toDomainKeyRotationLog(e *ent.KeyRotationLog) *domain.KeyRotationLog {
	return &domain.KeyRotationLog{
		ID:           e.ID,
		SigningKeyID: e.SigningKeyID,
		Action:       domain.KeyRotationAction(e.Action),
		TriggeredBy:  e.TriggeredBy,
		Reason:       e.Reason,
		CreatedAt:    e.CreatedAt,
	}
}
