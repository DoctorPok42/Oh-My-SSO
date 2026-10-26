package entstore

import (
	"context"
	"fmt"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/consent"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entConsentRepository struct {
	client *ent.Client
}

func NewConsentRepository(client *ent.Client) repository.ConsentRepository {
	return &entConsentRepository{client: client}
}

func (r *entConsentRepository) Create(ctx context.Context, p repository.CreateConsentParams) (*domain.Consent, error) {
	builder := r.client.Consent.
		Create().
		SetUserID(p.UserID).
		SetClientRefID(p.ClientRefID)
	if p.Scopes != nil {
		builder = builder.SetScopes(p.Scopes)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, fmt.Errorf("%w: %v", repository.ErrConflict, err)
		}
		return nil, err
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) GetByID(ctx context.Context, id string) (*domain.Consent, error) {
	e, err := r.client.Consent.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) GetByUserAndClient(ctx context.Context, userID, clientRefID string) (*domain.Consent, error) {
	e, err := r.client.Consent.
		Query().
		Where(consent.UserID(userID), consent.ClientRefID(clientRefID)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) ListByUser(ctx context.Context, userID string) ([]*domain.Consent, error) {
	rows, err := r.client.Consent.
		Query().
		Where(consent.UserID(userID)).
		Order(ent.Desc(consent.FieldUpdatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Consent, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainConsent(e))
	}
	return out, nil
}

func (r *entConsentRepository) Update(ctx context.Context, id string, p repository.UpdateConsentParams) (*domain.Consent, error) {
	builder := r.client.Consent.UpdateOneID(id)
	if p.Scopes != nil {
		builder = builder.SetScopes(p.Scopes)
	}
	if p.Status != nil {
		builder = builder.SetStatus(entschema.ConsentStatus(*p.Status))
	}
	if p.GrantedAt != nil {
		builder = builder.SetGrantedAt(*p.GrantedAt)
	}
	if p.ClearRevokedAt {
		builder = builder.ClearRevokedAt()
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.client.Consent.
		UpdateOneID(id).
		SetStatus(entschema.ConsentStatus(domain.ConsentRevoked)).
		SetRevokedAt(time.Now()).
		Save(ctx)
	return mapNotFound(err)
}

func (r *entConsentRepository) Delete(ctx context.Context, id string) error {
	return mapNotFound(r.client.Consent.DeleteOneID(id).Exec(ctx))
}

func toDomainConsent(e *ent.Consent) *domain.Consent {
	return &domain.Consent{
		ID:          e.ID,
		UserID:      e.UserID,
		ClientRefID: e.ClientRefID,
		Scopes:      e.Scopes,
		Status:      domain.ConsentStatus(e.Status),
		GrantedAt:   e.GrantedAt,
		RevokedAt:   e.RevokedAt,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
