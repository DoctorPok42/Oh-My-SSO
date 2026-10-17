package entstore

import (
	"context"
	"fmt"
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
	status := p.Status
	if status == "" {
		status = domain.MfaMethodActive
	}
	e, err := r.client.MfaMethod.
		Create().
		SetUserID(p.UserID).
		SetType(entschema.MfaMethodType(p.Type)).
		SetNillableName(nonEmpty(p.Name)).
		SetStatus(entschema.MfaMethodStatus(status)).
		SetNillableSecretEncrypted(nonEmpty(p.SecretEncrypted)).
		SetNillableCredentialID(nonEmpty(p.CredentialID)).
		SetNillablePublicKey(nonEmpty(p.PublicKey)).
		SetNillableWebauthnCredential(nonEmpty(p.WebAuthnCredential)).
		SetIsDiscoverable(p.IsDiscoverable).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, fmt.Errorf("%w: %v", repository.ErrConflict, err)
		}
		return nil, err
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) GetByID(ctx context.Context, id string) (*domain.MfaMethod, error) {
	e, err := r.client.MfaMethod.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) ListByUser(ctx context.Context, userID string) ([]*domain.MfaMethod, error) {
	rows, err := r.client.MfaMethod.Query().
		Where(mfamethod.UserID(userID)).
		Order(ent.Asc(mfamethod.FieldCreatedAt)).
		All(ctx)
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
	if p.Name != nil {
		builder = builder.SetName(*p.Name)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) MarkUsed(ctx context.Context, id string) error {
	_, err := r.client.MfaMethod.UpdateOneID(id).SetLastUsedAt(time.Now()).Save(ctx)
	return mapNotFound(err)
}

func (r *entMfaMethodRepository) Delete(ctx context.Context, id string) error {
	return mapNotFound(r.client.MfaMethod.DeleteOneID(id).Exec(ctx))
}

var (
	totpType      = entschema.MfaMethodType(domain.MfaMethodTOTP)
	activeMethod  = entschema.MfaMethodStatus(domain.MfaMethodActive)
	pendingMethod = entschema.MfaMethodStatus(domain.MfaMethodPending)
)

func (r *entMfaMethodRepository) ActivateTOTP(ctx context.Context, id string, counter int64, at time.Time) (*domain.MfaMethod, error) {
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}
	rollback := func(err error) (*domain.MfaMethod, error) {
		_ = tx.Rollback()
		return nil, err
	}

	pending, err := tx.MfaMethod.Query().
		Where(mfamethod.ID(id), mfamethod.TypeEQ(totpType), mfamethod.StatusEQ(pendingMethod)).
		Only(ctx)
	if err != nil {
		return rollback(mapNotFound(err))
	}

	// The partial unique index allows one active TOTP per user: remove the
	// previous one before activating the new one, in the same transaction.
	if _, err := tx.MfaMethod.Delete().
		Where(
			mfamethod.UserID(pending.UserID),
			mfamethod.TypeEQ(totpType),
			mfamethod.StatusEQ(activeMethod),
			mfamethod.IDNEQ(id),
		).
		Exec(ctx); err != nil {
		return rollback(fmt.Errorf("activate totp: delete previous: %w", err))
	}

	n, err := tx.MfaMethod.Update().
		Where(mfamethod.ID(id), mfamethod.StatusEQ(pendingMethod)).
		SetStatus(activeMethod).
		SetLastUsedCounter(counter).
		SetLastUsedAt(at).
		Save(ctx)
	if err != nil {
		return rollback(fmt.Errorf("activate totp: %w", err))
	}
	if n == 0 {
		return rollback(repository.ErrNotFound)
	}

	e, err := tx.MfaMethod.Get(ctx, id)
	if err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return toDomainMfaMethod(e), nil
}

func (r *entMfaMethodRepository) ConsumeTOTPCounter(ctx context.Context, id string, counter int64, at time.Time) (bool, error) {
	// A single conditional UPDATE: Postgres locks the row, so of two
	// concurrent requests with the same code, the second one sees the new
	// counter and matches no row.
	n, err := r.client.MfaMethod.Update().
		Where(
			mfamethod.ID(id),
			mfamethod.StatusEQ(activeMethod),
			mfamethod.LastUsedCounterLT(counter),
		).
		SetLastUsedCounter(counter).
		SetLastUsedAt(at).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *entMfaMethodRepository) DeletePendingByUser(ctx context.Context, userID string, t domain.MfaMethodType) (int, error) {
	return r.client.MfaMethod.Delete().
		Where(
			mfamethod.UserID(userID),
			mfamethod.TypeEQ(entschema.MfaMethodType(t)),
			mfamethod.StatusEQ(pendingMethod),
		).
		Exec(ctx)
}

func (r *entMfaMethodRepository) DeleteByUser(ctx context.Context, userID string) (int, error) {
	return r.client.MfaMethod.Delete().Where(mfamethod.UserID(userID)).Exec(ctx)
}

func (r *entMfaMethodRepository) UpdateWebAuthnCredential(ctx context.Context, id string, credentialJSON string, at time.Time) error {
	_, err := r.client.MfaMethod.UpdateOneID(id).
		SetWebauthnCredential(credentialJSON).
		SetLastUsedAt(at).
		Save(ctx)
	return mapNotFound(err)
}

func toDomainMfaMethod(e *ent.MfaMethod) *domain.MfaMethod {
	return &domain.MfaMethod{
		ID:                 e.ID,
		UserID:             e.UserID,
		Type:               domain.MfaMethodType(e.Type),
		Name:               e.Name,
		SecretEncrypted:    e.SecretEncrypted,
		CredentialID:       e.CredentialID,
		PublicKey:          e.PublicKey,
		IsDiscoverable:     e.IsDiscoverable,
		WebAuthnCredential: e.WebauthnCredential,
		Status:             domain.MfaMethodStatus(e.Status),
		CreatedAt:          e.CreatedAt,
		UpdatedAt:          e.UpdatedAt,
		LastUsedAt:         e.LastUsedAt,
		LastUsedCounter:    e.LastUsedCounter,
	}
}
