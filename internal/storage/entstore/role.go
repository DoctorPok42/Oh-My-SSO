package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/role"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entRoleRepository struct {
	client *ent.Client
}

func NewRoleRepository(client *ent.Client) repository.RoleRepository {
	return &entRoleRepository{client: client}
}

func (r *entRoleRepository) Create(ctx context.Context, p repository.CreateRoleParams) (*domain.Role, error) {
	e, err := r.client.Role.
		Create().
		SetRealmID(p.RealmID).
		SetName(p.Name).
		SetNillableDescription(nonEmpty(p.Description)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainRole(e), nil
}

func (r *entRoleRepository) GetByID(ctx context.Context, id string) (*domain.Role, error) {
	e, err := r.client.Role.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainRole(e), nil
}

func (r *entRoleRepository) GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.Role, error) {
	e, err := r.client.Role.
		Query().
		Where(role.RealmID(realmID), role.Name(name)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainRole(e), nil
}

func (r *entRoleRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.Role, error) {
	rows, err := r.client.Role.Query().Where(role.RealmID(realmID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Role, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainRole(e))
	}
	return out, nil
}

func (r *entRoleRepository) Update(ctx context.Context, id string, p repository.UpdateRoleParams) (*domain.Role, error) {
	builder := r.client.Role.UpdateOneID(id)
	if p.Name != nil {
		builder = builder.SetName(*p.Name)
	}
	builder = builder.SetNillableDescription(p.Description)
	if p.Status != nil {
		builder = builder.SetStatus(entschema.RoleStatus(*p.Status))
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainRole(e), nil
}

func (r *entRoleRepository) Delete(ctx context.Context, id string) error {
	return r.client.Role.DeleteOneID(id).Exec(ctx)
}

func toDomainRole(e *ent.Role) *domain.Role {
	return &domain.Role{
		ID:          e.ID,
		RealmID:     e.RealmID,
		ManagedBy:   domain.RoleManagedBy(e.ManagedBy),
		Name:        e.Name,
		Description: e.Description,
		Status:      domain.RoleStatus(e.Status),
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
