package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/passwordresettoken"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entPasswordResetTokenRepository struct {
	client *ent.Client
}

func NewPasswordResetTokenRepository(client *ent.Client) repository.PasswordResetTokenRepository {
	return &entPasswordResetTokenRepository{client: client}
}

func (r *entPasswordResetTokenRepository) Create(ctx context.Context, p repository.CreatePasswordResetTokenParams) (*domain.PasswordResetToken, error) {
	e, err := r.client.PasswordResetToken.
		Create().
		SetUserID(p.UserID).
		SetTokenHash(p.TokenHash).
		SetExpiresAt(p.ExpiresAt).
		SetNillableRequestedIP(nonEmpty(p.RequestedIP)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainPasswordResetToken(e), nil
}

func (r *entPasswordResetTokenRepository) GetByID(ctx context.Context, id string) (*domain.PasswordResetToken, error) {
	e, err := r.client.PasswordResetToken.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainPasswordResetToken(e), nil
}

func (r *entPasswordResetTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error) {
	e, err := r.client.PasswordResetToken.
		Query().
		Where(passwordresettoken.TokenHash(tokenHash)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainPasswordResetToken(e), nil
}

func (r *entPasswordResetTokenRepository) MarkUsed(ctx context.Context, id string) error {
	_, err := r.client.PasswordResetToken.
		UpdateOneID(id).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)
	return err
}

func (r *entPasswordResetTokenRepository) Delete(ctx context.Context, id string) error {
	return r.client.PasswordResetToken.DeleteOneID(id).Exec(ctx)
}

func toDomainPasswordResetToken(e *ent.PasswordResetToken) *domain.PasswordResetToken {
	return &domain.PasswordResetToken{
		ID:          e.ID,
		UserID:      e.UserID,
		TokenHash:   e.TokenHash,
		ExpiresAt:   e.ExpiresAt,
		Used:        e.Used,
		UsedAt:      e.UsedAt,
		RequestedIP: e.RequestedIP,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
