package entstore

import (
	"context"

	"sso.internal/sso/ent"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/token"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entTokenRepository struct {
	client *ent.Client
}

func NewTokenRepository(client *ent.Client) repository.TokenRepository {
	return &entTokenRepository{client: client}
}

func (r *entTokenRepository) Create(ctx context.Context, p repository.CreateTokenParams) (*domain.Token, error) {
	builder := r.client.Token.
		Create().
		SetSessionID(p.SessionID).
		SetClientRefID(p.ClientRefID).
		SetType(entschema.TokenType(p.Type)).
		SetJti(p.JTI).
		SetExpiresAt(p.ExpiresAt)
	if p.Scopes != nil {
		builder = builder.SetScopes(p.Scopes)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainToken(e), nil
}

func (r *entTokenRepository) GetByID(ctx context.Context, id string) (*domain.Token, error) {
	e, err := r.client.Token.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainToken(e), nil
}

func (r *entTokenRepository) GetByJTI(ctx context.Context, jti string) (*domain.Token, error) {
	e, err := r.client.Token.
		Query().
		Where(token.Jti(jti)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainToken(e), nil
}

func (r *entTokenRepository) ListBySession(ctx context.Context, sessionID string) ([]*domain.Token, error) {
	rows, err := r.client.Token.
		Query().
		Where(token.SessionID(sessionID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Token, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainToken(e))
	}
	return out, nil
}

func (r *entTokenRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.client.Token.UpdateOneID(id).SetRevoked(true).Save(ctx)
	return err
}

func (r *entTokenRepository) Delete(ctx context.Context, id string) error {
	return r.client.Token.DeleteOneID(id).Exec(ctx)
}

func toDomainToken(e *ent.Token) *domain.Token {
	return &domain.Token{
		ID:          e.ID,
		SessionID:   e.SessionID,
		ClientRefID: e.ClientRefID,
		Type:        domain.TokenType(e.Type),
		JTI:         e.Jti,
		IssuedAt:    e.IssuedAt,
		ExpiresAt:   e.ExpiresAt,
		Revoked:     e.Revoked,
		Scopes:      e.Scopes,
	}
}
