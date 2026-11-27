package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/apiresource"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entApiResourceRepository struct {
	client *ent.Client
}

func NewApiResourceRepository(client *ent.Client) repository.ApiResourceRepository {
	return &entApiResourceRepository{client: client}
}

func (r *entApiResourceRepository) Create(ctx context.Context, p repository.CreateApiResourceParams) (*domain.ApiResource, error) {
	e, err := r.client.ApiResource.Create().
		SetRealmID(p.RealmID).
		SetIdentifier(p.Identifier).
		SetName(p.Name).
		SetNillableDescription(nonEmpty(p.Description)).
		AddScopeIDs(p.ScopeIDs...).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return r.GetByID(ctx, e.ID)
}

func (r *entApiResourceRepository) GetByID(ctx context.Context, id string) (*domain.ApiResource, error) {
	e, err := r.client.ApiResource.Query().Where(apiresource.ID(id)).WithScopes().Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainApiResource(e), nil
}

func (r *entApiResourceRepository) GetByRealmAndIdentifier(ctx context.Context, realmID, identifier string) (*domain.ApiResource, error) {
	e, err := r.client.ApiResource.Query().
		Where(apiresource.RealmID(realmID), apiresource.Identifier(identifier)).
		WithScopes().
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainApiResource(e), nil
}

func (r *entApiResourceRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.ApiResource, error) {
	rows, err := r.client.ApiResource.Query().Where(apiresource.RealmID(realmID)).WithScopes().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ApiResource, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainApiResource(e))
	}
	return out, nil
}

func (r *entApiResourceRepository) Update(ctx context.Context, id string, p repository.UpdateApiResourceParams) (*domain.ApiResource, error) {
	builder := r.client.ApiResource.UpdateOneID(id).
		SetNillableName(p.Name).
		SetNillableDescription(p.Description)
	if p.ScopeIDs != nil {
		builder = builder.ClearScopes().AddScopeIDs(p.ScopeIDs...)
	}
	if err := builder.Exec(ctx); err != nil {
		return nil, mapNotFound(err)
	}
	return r.GetByID(ctx, id)
}

func (r *entApiResourceRepository) Delete(ctx context.Context, id string) error {
	return mapNotFound(r.client.ApiResource.DeleteOneID(id).Exec(ctx))
}

func toDomainApiResource(e *ent.ApiResource) *domain.ApiResource {
	out := &domain.ApiResource{
		ID:          e.ID,
		RealmID:     e.RealmID,
		Identifier:  e.Identifier,
		Name:        e.Name,
		Description: e.Description,
		Scopes:      make([]*domain.ClientScope, 0, len(e.Edges.Scopes)),
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
	for _, cs := range e.Edges.Scopes {
		out.Scopes = append(out.Scopes, toDomainClientScope(cs))
	}
	return out
}
