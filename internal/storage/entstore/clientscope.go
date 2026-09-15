package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/clientscope"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entClientScopeRepository struct {
	client *ent.Client
}

func NewClientScopeRepository(client *ent.Client) repository.ClientScopeRepository {
	return &entClientScopeRepository{client: client}
}

func (r *entClientScopeRepository) Create(ctx context.Context, p repository.CreateClientScopeParams) (*domain.ClientScope, error) {
	e, err := r.client.ClientScope.
		Create().
		SetRealmID(p.RealmID).
		SetName(p.Name).
		SetNillableDescription(nonEmpty(p.Description)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientScope(e), nil
}

func (r *entClientScopeRepository) GetByID(ctx context.Context, id string) (*domain.ClientScope, error) {
	e, err := r.client.ClientScope.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainClientScope(e), nil
}

func (r *entClientScopeRepository) GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.ClientScope, error) {
	e, err := r.client.ClientScope.
		Query().
		Where(clientscope.RealmID(realmID), clientscope.Name(name)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientScope(e), nil
}

func (r *entClientScopeRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.ClientScope, error) {
	rows, err := r.client.ClientScope.Query().Where(clientscope.RealmID(realmID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ClientScope, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainClientScope(e))
	}
	return out, nil
}

func (r *entClientScopeRepository) Update(ctx context.Context, id string, p repository.UpdateClientScopeParams) (*domain.ClientScope, error) {
	builder := r.client.ClientScope.UpdateOneID(id)
	if p.Name != nil {
		builder = builder.SetName(*p.Name)
	}
	builder = builder.SetNillableDescription(p.Description)
	if p.Protocol != nil {
		builder = builder.SetProtocol(entschema.ClientScopeProtocol(*p.Protocol))
	}
	if p.IsDefault != nil {
		builder = builder.SetIsDefault(*p.IsDefault)
	}
	if p.ClaimMappers != nil {
		builder = builder.SetClaimMappers(p.ClaimMappers)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientScope(e), nil
}

func (r *entClientScopeRepository) Delete(ctx context.Context, id string) error {
	return r.client.ClientScope.DeleteOneID(id).Exec(ctx)
}

func toDomainClientScope(e *ent.ClientScope) *domain.ClientScope {
	return &domain.ClientScope{
		ID:           e.ID,
		RealmID:      e.RealmID,
		Name:         e.Name,
		Description:  e.Description,
		Protocol:     domain.ClientScopeProtocol(e.Protocol),
		IsDefault:    e.IsDefault,
		ClaimMappers: e.ClaimMappers,
		CreatedAt:    e.CreatedAt,
		UpdatedAt:    e.UpdatedAt,
	}
}
