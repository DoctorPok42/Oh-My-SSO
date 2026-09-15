package entstore

import (
	"context"
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
		return nil, err
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) GetByID(ctx context.Context, id string) (*domain.Consent, error) {
	e, err := r.client.Consent.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) GetByUserAndClient(ctx context.Context, userID, clientRefID string) (*domain.Consent, error) {
	e, err := r.client.Consent.
		Query().
		Where(consent.UserID(userID), consent.ClientRefID(clientRefID)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) Update(ctx context.Context, id string, p repository.UpdateConsentParams) (*domain.Consent, error) {
	builder := r.client.Consent.UpdateOneID(id)
	if p.Scopes != nil {
		builder = builder.SetScopes(p.Scopes)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainConsent(e), nil
}

func (r *entConsentRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.client.Consent.
		UpdateOneID(id).
		SetStatus(entschema.ConsentStatus(domain.ConsentRevoked)).
		SetRevokedAt(time.Now()).
		Save(ctx)
	return err
}

func (r *entConsentRepository) Delete(ctx context.Context, id string) error {
	return r.client.Consent.DeleteOneID(id).Exec(ctx)
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
