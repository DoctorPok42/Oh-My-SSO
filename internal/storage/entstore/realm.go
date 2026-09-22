package entstore

import (
	"context"
	"slices"
	"strings"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/realm"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

var reservedRealmNames = []string{
	"health",
	"metrics",
	"master",
	"admin",
	"api",
	"static",
	"assets",
	"well-known",
}

func isReservedRealmName(name string) bool {
	return slices.ContainsFunc(reservedRealmNames, func(reserved string) bool {
		return strings.EqualFold(reserved, name)
	})
}

type entRealmRepository struct {
	client *ent.Client
}

func NewRealmRepository(client *ent.Client) repository.RealmRepository {
	return &entRealmRepository{client: client}
}

func (r *entRealmRepository) Create(ctx context.Context, p repository.CreateRealmParams) (*domain.Realm, error) {
	if isReservedRealmName(p.Name) {
		return nil, repository.ErrReservedRealmName
	}

	e, err := r.client.Realm.
		Create().
		SetName(p.Name).
		SetNillableDisplayName(nonEmpty(p.DisplayName)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainRealm(e), nil
}

func (r *entRealmRepository) GetByID(ctx context.Context, id string) (*domain.Realm, error) {
	e, err := r.client.Realm.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toDomainRealm(e), nil
}

func (r *entRealmRepository) GetByName(ctx context.Context, name string) (*domain.Realm, error) {
	e, err := r.client.Realm.
		Query().
		Where(realm.NameEQ(name)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toDomainRealm(e), nil
}

func (r *entRealmRepository) Update(ctx context.Context, id string, p repository.UpdateRealmParams) (*domain.Realm, error) {
	if p.Name != nil && isReservedRealmName(*p.Name) {
		return nil, repository.ErrReservedRealmName
	}

	builder := r.client.Realm.UpdateOneID(id)

	if p.Name != nil {
		builder = builder.SetName(*p.Name)
	}
	builder = builder.SetNillableDisplayName(p.DisplayName)
	if p.Status != nil {
		builder = builder.SetStatus(entschema.RealmStatus(*p.Status))
	}

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainRealm(e), nil
}

func (r *entRealmRepository) Delete(ctx context.Context, id string) error {
	return r.client.Realm.DeleteOneID(id).Exec(ctx)
}

func toDomainRealm(e *ent.Realm) *domain.Realm {
	return &domain.Realm{
		ID:            e.ID,
		Name:          e.Name,
		IsSystemRealm: e.IsSystemRealm,
		DisplayName:   e.DisplayName,
		Status:        domain.RealmStatus(e.Status),
		CreatedAt:     e.CreatedAt,
		UpdatedAt:     e.UpdatedAt,
	}
}
