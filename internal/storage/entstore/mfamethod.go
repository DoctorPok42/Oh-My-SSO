package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/mfamethod"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entMfaMethodRepository struct {
	client *ent.Client
}

func NewMfaMethodRepository(client *ent.Client) repository.MfaMethodRepository {
	return &entMfaMethodRepository{client: client}
}

func (r *entMfaMethodRepository) Create(ctx context.Context, p repository.CreateMfaMethodParams) (*domain.MfaMethod, error) {
	e, err := r.client.MfaMethod.
		Create().
		SetUserID(p.UserID).
		SetType(entschema.MfaMethodType(p.Type)).
		SetNillableSecretEncrypted(nonEmpty(p.SecretEncrypted)).
		SetNillableCredentialID(nonEmpty(p.CredentialID)).
		SetNillablePublicKey(nonEmpty(p.PublicKey)).
		SetIsDiscoverable(p.IsDiscoverable).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) GetByID(ctx context.Context, id string) (*domain.MfaMethod, error) {
	e, err := r.client.MfaMethod.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) ListByUser(ctx context.Context, userID string) ([]*domain.MfaMethod, error) {
	rows, err := r.client.MfaMethod.Query().Where(mfamethod.UserID(userID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.MfaMethod, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainMfaMethod(e))
	}
	return out, nil
}

func (r *entMfaMethodRepository) Update(ctx context.Context, id string, p repository.UpdateMfaMethodParams) (*domain.MfaMethod, error) {
	builder := r.client.MfaMethod.UpdateOneID(id)
	if p.Status != nil {
		builder = builder.SetStatus(entschema.MfaMethodStatus(*p.Status))
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) MarkUsed(ctx context.Context, id string) error {
	_, err := r.client.MfaMethod.UpdateOneID(id).SetLastUsedAt(time.Now()).Save(ctx)
	return err
}

func (r *entMfaMethodRepository) Delete(ctx context.Context, id string) error {
	return r.client.MfaMethod.DeleteOneID(id).Exec(ctx)
}

func toDomainMfaMethod(e *ent.MfaMethod) *domain.MfaMethod {
	return &domain.MfaMethod{
		ID:              e.ID,
		UserID:          e.UserID,
		Type:            domain.MfaMethodType(e.Type),
		SecretEncrypted: e.SecretEncrypted,
		CredentialID:    e.CredentialID,
		PublicKey:       e.PublicKey,
		IsDiscoverable:  e.IsDiscoverable,
		Status:          domain.MfaMethodStatus(e.Status),
		CreatedAt:       e.CreatedAt,
		UpdatedAt:       e.UpdatedAt,
		LastUsedAt:      e.LastUsedAt,
	}
}
