package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/mfabackupcode"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entMfaBackupCodeRepository struct {
	client *ent.Client
}

func NewMfaBackupCodeRepository(client *ent.Client) repository.MfaBackupCodeRepository {
	return &entMfaBackupCodeRepository{client: client}
}

func (r *entMfaBackupCodeRepository) Create(ctx context.Context, p repository.CreateMfaBackupCodeParams) (*domain.MfaBackupCode, error) {
	e, err := r.client.MfaBackupCode.
		Create().
		SetUserID(p.UserID).
		SetBatchID(p.BatchID).
		SetCodeHash(p.CodeHash).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaBackupCode(e), nil
}

func (r *entMfaBackupCodeRepository) GetByID(ctx context.Context, id string) (*domain.MfaBackupCode, error) {
	e, err := r.client.MfaBackupCode.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainMfaBackupCode(e), nil
}

func (r *entMfaBackupCodeRepository) ListByUser(ctx context.Context, userID string) ([]*domain.MfaBackupCode, error) {
	rows, err := r.client.MfaBackupCode.Query().Where(mfabackupcode.UserID(userID)).All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaBackupCodes(rows), nil
}

func (r *entMfaBackupCodeRepository) ListByBatch(ctx context.Context, userID, batchID string) ([]*domain.MfaBackupCode, error) {
	rows, err := r.client.MfaBackupCode.
		Query().
		Where(mfabackupcode.UserID(userID), mfabackupcode.BatchID(batchID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaBackupCodes(rows), nil
}

func (r *entMfaBackupCodeRepository) GetByCodeHash(ctx context.Context, codeHash string) (*domain.MfaBackupCode, error) {
	e, err := r.client.MfaBackupCode.
		Query().
		Where(mfabackupcode.CodeHash(codeHash)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaBackupCode(e), nil
}

func (r *entMfaBackupCodeRepository) MarkUsed(ctx context.Context, id string) error {
	_, err := r.client.MfaBackupCode.
		UpdateOneID(id).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)
	return err
}

func (r *entMfaBackupCodeRepository) DeleteByBatch(ctx context.Context, userID, batchID string) error {
	_, err := r.client.MfaBackupCode.
		Delete().
		Where(mfabackupcode.UserID(userID), mfabackupcode.BatchID(batchID)).
		Exec(ctx)
	return err
}

func (r *entMfaBackupCodeRepository) Delete(ctx context.Context, id string) error {
	return r.client.MfaBackupCode.DeleteOneID(id).Exec(ctx)
}

func toDomainMfaBackupCodes(rows []*ent.MfaBackupCode) []*domain.MfaBackupCode {
	out := make([]*domain.MfaBackupCode, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainMfaBackupCode(e))
	}
	return out
}

func toDomainMfaBackupCode(e *ent.MfaBackupCode) *domain.MfaBackupCode {
	return &domain.MfaBackupCode{
		ID:        e.ID,
		UserID:    e.UserID,
		BatchID:   e.BatchID,
		CodeHash:  e.CodeHash,
		Used:      e.Used,
		UsedAt:    e.UsedAt,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
}
