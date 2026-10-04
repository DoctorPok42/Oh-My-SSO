package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/clientapp"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entAccessRepository struct {
	client *ent.Client
}

func NewAccessRepository(client *ent.Client) repository.AccessRepository {
	return &entAccessRepository{client: client}
}

func (r *entAccessRepository) GetUserAccess(ctx context.Context, userID string) (*domain.UserAccess, error) {
	u, err := r.client.User.Query().
		Where(user.ID(userID), user.DeletedAtIsNil()).
		WithRoles(func(q *ent.RoleQuery) {
			q.WithPermissions().WithClientScopes()
		}).
		WithGroups(func(q *ent.GroupQuery) {
			q.WithPermissions().WithClientScopes()
		}).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}

	access := &domain.UserAccess{
		UserID:  u.ID,
		RealmID: u.RealmID,
		Status:  domain.UserStatus(u.Status),
		Roles:   make([]domain.AccessSource, 0, len(u.Edges.Roles)),
		Groups:  make([]domain.AccessSource, 0, len(u.Edges.Groups)),
	}
	for _, ro := range u.Edges.Roles {
		access.Roles = append(access.Roles, domain.AccessSource{
			Kind:         domain.AccessSourceRole,
			ID:           ro.ID,
			RealmID:      ro.RealmID,
			Name:         ro.Name,
			Active:       ro.Status == entschema.RoleActive,
			Permissions:  toDomainPermissions(ro.Edges.Permissions),
			ClientScopes: toDomainClientScopes(ro.Edges.ClientScopes),
		})
	}
	for _, g := range u.Edges.Groups {
		access.Groups = append(access.Groups, domain.AccessSource{
			Kind:         domain.AccessSourceGroup,
			ID:           g.ID,
			RealmID:      g.RealmID,
			Name:         g.Name,
			Active:       g.Status == entschema.GroupActive,
			Permissions:  toDomainPermissions(g.Edges.Permissions),
			ClientScopes: toDomainClientScopes(g.Edges.ClientScopes),
		})
	}
	return access, nil
}

func (r *entAccessRepository) GetClientAccessPolicy(ctx context.Context, clientRef string) (*domain.ClientAccessPolicy, error) {
	c, err := r.client.ClientApp.Query().
		Where(clientapp.ID(clientRef), clientapp.DeletedAtIsNil()).
		WithRoles().        // through ClientRole
		WithGroups().       // through ClientGroup
		WithClientScopes(). // through ClientScopeMapping
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}

	policy := &domain.ClientAccessPolicy{
		ClientRef: c.ID,
		RealmID:   c.RealmID,
		Status:    domain.ClientAppStatus(c.Status),
		RoleIDs:   make([]string, 0, len(c.Edges.Roles)),
		GroupIDs:  make([]string, 0, len(c.Edges.Groups)),
		ScopeIDs:  make([]string, 0, len(c.Edges.ClientScopes)),
	}
	for _, ro := range c.Edges.Roles {
		policy.RoleIDs = append(policy.RoleIDs, ro.ID)
	}
	for _, g := range c.Edges.Groups {
		policy.GroupIDs = append(policy.GroupIDs, g.ID)
	}
	for _, cs := range c.Edges.ClientScopes {
		policy.ScopeIDs = append(policy.ScopeIDs, cs.ID)
	}
	return policy, nil
}

func toDomainPermissions(rows []*ent.Permission) []*domain.Permission {
	out := make([]*domain.Permission, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainPermission(e))
	}
	return out
}

func toDomainClientScopes(rows []*ent.ClientScope) []*domain.ClientScope {
	out := make([]*domain.ClientScope, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainClientScope(e))
	}
	return out
}
