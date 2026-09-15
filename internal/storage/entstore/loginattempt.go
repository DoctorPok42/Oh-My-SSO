package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/loginattempt"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entLoginAttemptRepository struct {
	client *ent.Client
}

func NewLoginAttemptRepository(client *ent.Client) repository.LoginAttemptRepository {
	return &entLoginAttemptRepository{client: client}
}

func (r *entLoginAttemptRepository) Create(ctx context.Context, p repository.CreateLoginAttemptParams) (*domain.LoginAttempt, error) {
	e, err := r.client.LoginAttempt.
		Create().
		SetIdentifier(p.Identifier).
		SetNillableIPAddress(nonEmpty(p.IPAddress)).
		SetNillableUserAgent(nonEmpty(p.UserAgent)).
		SetStatus(entschema.LoginAttemptStatus(p.Status)).
		SetNillableFailureReason(nonEmpty(string(p.FailureReason))).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainLoginAttempt(e), nil
}

func (r *entLoginAttemptRepository) GetByID(ctx context.Context, id string) (*domain.LoginAttempt, error) {
	e, err := r.client.LoginAttempt.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainLoginAttempt(e), nil
}

func (r *entLoginAttemptRepository) ListByIdentifier(ctx context.Context, identifier string) ([]*domain.LoginAttempt, error) {
	rows, err := r.client.LoginAttempt.
		Query().
		Where(loginattempt.Identifier(identifier)).
		Order(ent.Desc(loginattempt.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainLoginAttempts(rows), nil
}

func (r *entLoginAttemptRepository) ListByIP(ctx context.Context, ipAddress string) ([]*domain.LoginAttempt, error) {
	rows, err := r.client.LoginAttempt.
		Query().
		Where(loginattempt.IPAddress(ipAddress)).
		Order(ent.Desc(loginattempt.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainLoginAttempts(rows), nil
}

func toDomainLoginAttempts(rows []*ent.LoginAttempt) []*domain.LoginAttempt {
	out := make([]*domain.LoginAttempt, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainLoginAttempt(e))
	}
	return out
}

func toDomainLoginAttempt(e *ent.LoginAttempt) *domain.LoginAttempt {
	return &domain.LoginAttempt{
		ID:            e.ID,
		Identifier:    e.Identifier,
		IPAddress:     e.IPAddress,
		UserAgent:     e.UserAgent,
		Status:        domain.LoginAttemptStatus(e.Status),
		FailureReason: domain.LoginAttemptFailureReason(e.FailureReason),
		CreatedAt:     e.CreatedAt,
	}
}
