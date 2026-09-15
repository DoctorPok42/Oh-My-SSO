package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/group"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entGroupRepository struct {
	client *ent.Client
}

func NewGroupRepository(client *ent.Client) repository.GroupRepository {
	return &entGroupRepository{client: client}
}

func (r *entGroupRepository) Create(ctx context.Context, p repository.CreateGroupParams) (*domain.Group, error) {
	e, err := r.client.Group.
		Create().
		SetRealmID(p.RealmID).
		SetName(p.Name).
		SetNillableDescription(nonEmpty(p.Description)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainGroup(e), nil
}

func (r *entGroupRepository) GetByID(ctx context.Context, id string) (*domain.Group, error) {
	e, err := r.client.Group.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainGroup(e), nil
}

func (r *entGroupRepository) GetByRealmAndName(ctx context.Context, realmID, name string) (*domain.Group, error) {
	e, err := r.client.Group.
		Query().
		Where(group.RealmID(realmID), group.Name(name)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainGroup(e), nil
}

func (r *entGroupRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.Group, error) {
	rows, err := r.client.Group.Query().Where(group.RealmID(realmID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Group, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainGroup(e))
	}
	return out, nil
}

func (r *entGroupRepository) Update(ctx context.Context, id string, p repository.UpdateGroupParams) (*domain.Group, error) {
	builder := r.client.Group.UpdateOneID(id)
	if p.Name != nil {
		builder = builder.SetName(*p.Name)
	}
	builder = builder.SetNillableDescription(p.Description)
	if p.Status != nil {
		builder = builder.SetStatus(entschema.GroupStatus(*p.Status))
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainGroup(e), nil
}

func (r *entGroupRepository) Delete(ctx context.Context, id string) error {
	return r.client.Group.DeleteOneID(id).Exec(ctx)
}

func toDomainGroup(e *ent.Group) *domain.Group {
	return &domain.Group{
		ID:          e.ID,
		RealmID:     e.RealmID,
		ManagedBy:   domain.GroupManagedBy(e.ManagedBy),
		Name:        e.Name,
		Description: e.Description,
		Status:      domain.GroupStatus(e.Status),
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
