package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/timeout"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entTimeoutRepository struct {
	client *ent.Client
}

func NewTimeoutRepository(client *ent.Client) repository.TimeoutRepository {
	return &entTimeoutRepository{client: client}
}

func (r *entTimeoutRepository) Create(ctx context.Context, p repository.CreateTimeoutParams) (*domain.Timeout, error) {
	builder := r.client.Timeout.
		Create().
		SetRealmID(p.RealmID).
		SetTargetType(entschema.TimeoutTargetType(p.TargetType)).
		SetTargetID(p.TargetID).
		SetStartsAt(p.StartsAt).
		SetReason(p.Reason).
		SetCreatedBy(p.CreatedBy)
	if !p.EndsAt.IsZero() {
		builder = builder.SetEndsAt(p.EndsAt)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainTimeout(e), nil
}

func (r *entTimeoutRepository) GetByID(ctx context.Context, id string) (*domain.Timeout, error) {
	e, err := r.client.Timeout.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainTimeout(e), nil
}

func (r *entTimeoutRepository) ListActiveForTarget(ctx context.Context, targetType domain.TimeoutTargetType, targetID string) ([]*domain.Timeout, error) {
	rows, err := r.client.Timeout.
		Query().
		Where(
			timeout.TargetType(entschema.TimeoutTargetType(targetType)),
			timeout.TargetID(targetID),
			timeout.Or(
				timeout.EndsAtIsNil(),
				timeout.EndsAtGT(time.Now()),
			),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Timeout, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainTimeout(e))
	}
	return out, nil
}

func (r *entTimeoutRepository) Update(ctx context.Context, id string, p repository.UpdateTimeoutParams) (*domain.Timeout, error) {
	builder := r.client.Timeout.UpdateOneID(id)
	if p.Reason != nil {
		builder = builder.SetReason(*p.Reason)
	}
	if p.EndsAt != nil {
		builder = builder.SetEndsAt(*p.EndsAt)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainTimeout(e), nil
}

func (r *entTimeoutRepository) Lift(ctx context.Context, id string) error {
	_, err := r.client.Timeout.UpdateOneID(id).SetEndsAt(time.Now()).Save(ctx)
	return err
}

func (r *entTimeoutRepository) Delete(ctx context.Context, id string) error {
	return r.client.Timeout.DeleteOneID(id).Exec(ctx)
}

func toDomainTimeout(e *ent.Timeout) *domain.Timeout {
	return &domain.Timeout{
		ID:         e.ID,
		RealmID:    e.RealmID,
		TargetType: domain.TimeoutTargetType(e.TargetType),
		TargetID:   e.TargetID,
		StartsAt:   e.StartsAt,
		EndsAt:     e.EndsAt,
		Reason:     e.Reason,
		CreatedBy:  e.CreatedBy,
		CreatedAt:  e.CreatedAt,
	}
}
