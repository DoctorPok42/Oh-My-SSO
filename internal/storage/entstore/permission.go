package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/permission"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entPermissionRepository struct {
	client *ent.Client
}

func NewPermissionRepository(client *ent.Client) repository.PermissionRepository {
	return &entPermissionRepository{client: client}
}

func (r *entPermissionRepository) Create(ctx context.Context, p repository.CreatePermissionParams) (*domain.Permission, error) {
	builder := r.client.Permission.
		Create().
		SetRealmID(p.RealmID).
		SetName(p.Name).
		SetNillableDescription(nonEmpty(p.Description)).
		SetResource(p.Resource).
		SetAction(p.Action).
		SetScope(p.Scope)
	if p.Constraints != nil {
		builder = builder.SetConstraints(p.Constraints)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainPermission(e), nil
}

func (r *entPermissionRepository) GetByID(ctx context.Context, id string) (*domain.Permission, error) {
	e, err := r.client.Permission.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainPermission(e), nil
}

func (r *entPermissionRepository) GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.Permission, error) {
	e, err := r.client.Permission.
		Query().
		Where(permission.RealmID(realmID), permission.Name(name)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainPermission(e), nil
}

func (r *entPermissionRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.Permission, error) {
	rows, err := r.client.Permission.Query().Where(permission.RealmID(realmID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Permission, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainPermission(e))
	}
	return out, nil
}

func (r *entPermissionRepository) Update(ctx context.Context, id string, p repository.UpdatePermissionParams) (*domain.Permission, error) {
	builder := r.client.Permission.UpdateOneID(id)
	builder = builder.SetNillableDescription(p.Description)
	if p.Status != nil {
		builder = builder.SetStatus(entschema.PermissionStatus(*p.Status))
	}
	if p.Resource != nil {
		builder = builder.SetResource(*p.Resource)
	}
	if p.Action != nil {
		builder = builder.SetAction(*p.Action)
	}
	if p.Scope != nil {
		builder = builder.SetScope(*p.Scope)
	}
	if p.Constraints != nil {
		builder = builder.SetConstraints(p.Constraints)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainPermission(e), nil
}

func (r *entPermissionRepository) Delete(ctx context.Context, id string) error {
	return r.client.Permission.DeleteOneID(id).Exec(ctx)
}

func toDomainPermission(e *ent.Permission) *domain.Permission {
	return &domain.Permission{
		ID:          e.ID,
		RealmID:     e.RealmID,
		Name:        e.Name,
		Description: e.Description,
		Status:      domain.PermissionStatus(e.Status),
		Resource:    e.Resource,
		Action:      e.Action,
		Scope:       e.Scope,
		Constraints: e.Constraints,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
