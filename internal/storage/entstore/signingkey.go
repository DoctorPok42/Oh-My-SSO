package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/signingkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entSigningKeyRepository struct {
	client *ent.Client
}

func NewSigningKeyRepository(client *ent.Client) repository.SigningKeyRepository {
	return &entSigningKeyRepository{client: client}
}

func (r *entSigningKeyRepository) Create(ctx context.Context, p repository.CreateSigningKeyParams) (*domain.SigningKey, error) {
	e, err := r.client.SigningKey.
		Create().
		SetRealmID(p.RealmID).
		SetKeyType(entschema.SigningKeyType(p.KeyType)).
		SetPurpose(entschema.SigningKeyPurpose(p.Purpose)).
		SetKmsKeyReference(p.KMSKeyReference).
		SetKmsBackend(p.KMSBackend).
		SetNillablePublicKey(nonEmpty(p.PublicKey)).
		SetKid(p.Kid).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainSigningKey(e), nil
}

func (r *entSigningKeyRepository) GetByID(ctx context.Context, id string) (*domain.SigningKey, error) {
	e, err := r.client.SigningKey.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainSigningKey(e), nil
}

func (r *entSigningKeyRepository) GetByKid(ctx context.Context, kid string) (*domain.SigningKey, error) {
	e, err := r.client.SigningKey.
		Query().
		Where(signingkey.Kid(kid)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainSigningKey(e), nil
}

func (r *entSigningKeyRepository) ListActiveByRealm(ctx context.Context, realmID string) ([]*domain.SigningKey, error) {
	rows, err := r.client.SigningKey.
		Query().
		Where(
			signingkey.RealmID(realmID),
			signingkey.StatusIn(
				entschema.SigningKeyStatus(domain.SigningKeyActive),
				entschema.SigningKeyStatus(domain.SigningKeyRotating),
			),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.SigningKey, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainSigningKey(e))
	}
	return out, nil
}

func (r *entSigningKeyRepository) SetStatus(ctx context.Context, id string, status domain.SigningKeyStatus) error {
	_, err := r.client.SigningKey.
		UpdateOneID(id).
		SetStatus(entschema.SigningKeyStatus(status)).
		Save(ctx)
	return err
}

func (r *entSigningKeyRepository) Retire(ctx context.Context, id string) error {
	_, err := r.client.SigningKey.
		UpdateOneID(id).
		SetStatus(entschema.SigningKeyStatus(domain.SigningKeyRetired)).
		SetRetiredAt(time.Now()).
		Save(ctx)
	return err
}

func (r *entSigningKeyRepository) Delete(ctx context.Context, id string) error {
	return r.client.SigningKey.DeleteOneID(id).Exec(ctx)
}

func toDomainSigningKey(e *ent.SigningKey) *domain.SigningKey {
	return &domain.SigningKey{
		ID:              e.ID,
		RealmID:         e.RealmID,
		KeyType:         domain.SigningKeyType(e.KeyType),
		Purpose:         domain.SigningKeyPurpose(e.Purpose),
		KMSKeyReference: e.KmsKeyReference,
		KMSBackend:      e.KmsBackend,
		PublicKey:       e.PublicKey,
		Kid:             e.Kid,
		Status:          domain.SigningKeyStatus(e.Status),
		CreatedAt:       e.CreatedAt,
		UpdatedAt:       e.UpdatedAt,
		RetiredAt:       e.RetiredAt,
	}
}
