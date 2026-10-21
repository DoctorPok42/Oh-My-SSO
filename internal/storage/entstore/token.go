package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/session"
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
	if p.TokenHash != "" {
		builder = builder.SetTokenHash(p.TokenHash)
	}
	if p.FamilyID != "" {
		builder = builder.SetFamilyID(p.FamilyID)
	}
	if p.Subject != "" {
		builder = builder.SetSubject(p.Subject)
	}
	if p.SubjectFormat != "" {
		builder = builder.SetSubjectFormat(p.SubjectFormat)
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
		return nil, mapNotFound(err)
	}
	return toDomainToken(e), nil
}

func (r *entTokenRepository) GetByJTI(ctx context.Context, jti string) (*domain.Token, error) {
	e, err := r.client.Token.
		Query().
		Where(token.Jti(jti)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainToken(e), nil
}

func (r *entTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*domain.Token, error) {
	if tokenHash == "" {
		return nil, repository.ErrNotFound
	}
	e, err := r.client.Token.
		Query().
		Where(token.TokenHash(tokenHash)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
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
	return mapNotFound(err)
}

// MarkUsed is a single conditional UPDATE: the database decides which of two
// concurrent refreshes wins, no read-then-write race is possible.
func (r *entTokenRepository) MarkUsed(ctx context.Context, id string, at time.Time) (bool, error) {
	n, err := r.client.Token.Update().
		Where(token.ID(id), token.UsedAtIsNil(), token.Revoked(false)).
		SetUsedAt(at).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *entTokenRepository) RevokeFamily(ctx context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	return r.client.Token.Update().
		Where(token.FamilyID(familyID), token.Revoked(false)).
		SetRevoked(true).
		Save(ctx)
}

// RevokeByUserAndClient is one UPDATE ... WHERE: the tokens are found through
// their session (sessions carry the user id, tokens do not).
func (r *entTokenRepository) RevokeByUserAndClient(ctx context.Context, userID, clientRefID string) (int, error) {
	if userID == "" || clientRefID == "" {
		return 0, nil
	}
	return r.client.Token.Update().
		Where(
			token.ClientRefID(clientRefID),
			token.Revoked(false),
			token.TypeIn(
				entschema.TokenType(domain.TokenAccessToken),
				entschema.TokenType(domain.TokenRefreshToken),
				entschema.TokenType(domain.TokenIDToken),
			),
			token.HasSessionWith(session.UserID(userID)),
		).
		SetRevoked(true).
		Save(ctx)
}

func (r *entTokenRepository) Delete(ctx context.Context, id string) error {
	return r.client.Token.DeleteOneID(id).Exec(ctx)
}

func toDomainToken(e *ent.Token) *domain.Token {
	t := &domain.Token{
		ID:          e.ID,
		SessionID:   e.SessionID,
		ClientRefID: e.ClientRefID,
		Type:        domain.TokenType(e.Type),
		JTI:         e.Jti,
		IssuedAt:    e.IssuedAt,
		ExpiresAt:   e.ExpiresAt,
		Revoked:     e.Revoked,
		Scopes:      e.Scopes,
		TokenHash:   e.TokenHash,
		FamilyID:    e.FamilyID,

		Subject:       e.Subject,
		SubjectFormat: e.SubjectFormat,
	}
	if e.UsedAt != nil {
		t.UsedAt = *e.UsedAt
	}
	return t
}
