package entstore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

type rbacFixture struct {
	t      *testing.T
	ctx    context.Context
	client *ent.Client
	realm  *domain.Realm
}

func newRBACFixture(t *testing.T) *rbacFixture {
	t.Helper()
	ctx := context.Background()
	client := newTestClient(t)
	return &rbacFixture{t: t, ctx: ctx, client: client, realm: newTestRealm(t, ctx, client)}
}

func (f *rbacFixture) suffix() string { return uuid.NewString()[:8] }

func (f *rbacFixture) user() *domain.User {
	f.t.Helper()
	name := "user-" + f.suffix()
	u, err := entstore.NewUserRepository(f.client).Create(f.ctx, repository.CreateUserParams{
		RealmID:  f.realm.ID,
		Username: name,
		Email:    name + "@example.test",
		Status:   domain.UserActive,
	})
	require.NoError(f.t, err)
	return u
}

func (f *rbacFixture) role() *domain.Role {
	f.t.Helper()
	r, err := entstore.NewRoleRepository(f.client).Create(f.ctx, repository.CreateRoleParams{
		RealmID: f.realm.ID, Name: "role-" + f.suffix(),
	})
	require.NoError(f.t, err)
	return r
}

func (f *rbacFixture) group() *domain.Group {
	f.t.Helper()
	g, err := entstore.NewGroupRepository(f.client).Create(f.ctx, repository.CreateGroupParams{
		RealmID: f.realm.ID, Name: "group-" + f.suffix(),
	})
	require.NoError(f.t, err)
	return g
}

func (f *rbacFixture) permission(resource, action string) *domain.Permission {
	f.t.Helper()
	p, err := entstore.NewPermissionRepository(f.client).Create(f.ctx, repository.CreatePermissionParams{
		RealmID:  f.realm.ID,
		Name:     resource + ":" + action + "-" + f.suffix(),
		Resource: resource,
		Action:   action,
		Scope:    "realm",
	})
	require.NoError(f.t, err)
	return p
}

func (f *rbacFixture) clientScope(name string) *domain.ClientScope {
	f.t.Helper()
	cs, err := entstore.NewClientScopeRepository(f.client).Create(f.ctx, repository.CreateClientScopeParams{
		RealmID: f.realm.ID, Name: name + "-" + f.suffix(),
	})
	require.NoError(f.t, err)
	return cs
}

func (f *rbacFixture) clientApp(name string) *domain.ClientApp {
	f.t.Helper()
	c, err := entstore.NewClientRepository(f.client).Create(f.ctx, repository.CreateClientAppParams{
		RealmID: f.realm.ID, Name: name + "-" + f.suffix(), Protocol: domain.ClientAppProtocolOIDC,
	})
	require.NoError(f.t, err)
	return c
}

func (f *rbacFixture) assignRole(u *domain.User, r *domain.Role) {
	f.t.Helper()
	require.NoError(f.t, f.client.User.UpdateOneID(u.ID).AddRoleIDs(r.ID).Exec(f.ctx))
}

func (f *rbacFixture) addToGroup(u *domain.User, g *domain.Group) {
	f.t.Helper()
	require.NoError(f.t, f.client.User.UpdateOneID(u.ID).AddGroupIDs(g.ID).Exec(f.ctx))
}

func (f *rbacFixture) grantPermissionToRole(r *domain.Role, p *domain.Permission) {
	f.t.Helper()
	require.NoError(f.t, f.client.Role.UpdateOneID(r.ID).AddPermissionIDs(p.ID).Exec(f.ctx))
}

func (f *rbacFixture) allowRoleOnClient(c *domain.ClientApp, r *domain.Role) {
	f.t.Helper()
	_, err := f.client.ClientRole.Create().SetClientAppID(c.ID).SetRoleID(r.ID).Save(f.ctx)
	require.NoError(f.t, err)
}

func (f *rbacFixture) allowGroupOnClient(c *domain.ClientApp, g *domain.Group) {
	f.t.Helper()
	_, err := f.client.ClientGroup.Create().SetClientAppID(c.ID).SetGroupID(g.ID).Save(f.ctx)
	require.NoError(f.t, err)
}

func (f *rbacFixture) grantScopeToGroup(g *domain.Group, cs *domain.ClientScope) {
	f.t.Helper()
	_, err := f.client.GroupClientScope.Create().SetGroupID(g.ID).SetClientScopeID(cs.ID).Save(f.ctx)
	require.NoError(f.t, err)
}

func (f *rbacFixture) mapScopeToClient(c *domain.ClientApp, cs *domain.ClientScope) {
	f.t.Helper()
	_, err := f.client.ClientScopeMapping.Create().SetClientAppID(c.ID).SetClientScopeID(cs.ID).Save(f.ctx)
	require.NoError(f.t, err)
}

func (f *rbacFixture) rbacService() *service.RBACService {
	return service.NewRBACService(
		entstore.NewAccessRepository(f.client),
		entstore.NewAuditLogRepository(f.client),
	)
}

// DoD 1: a role allowed on Client A but not on Client B must discriminate
// access between the two Clients.
func TestRBAC_RoleAllowedOnOneClientOnly_Integration(t *testing.T) {
	f := newRBACFixture(t)
	rbac := f.rbacService()

	u := f.user()
	r := f.role()
	p := f.permission("client", "read")
	clientA := f.clientApp("client-a")
	clientB := f.clientApp("client-b")

	f.assignRole(u, r)
	f.grantPermissionToRole(r, p)
	f.allowRoleOnClient(clientA, r) // nothing on clientB

	// Client A: the role's permission is effective.
	permsA, err := rbac.GetEffectivePermissions(f.ctx, u.ID, clientA.ID)
	require.NoError(t, err)
	require.Len(t, permsA, 1)
	require.Equal(t, p.ID, permsA[0].ID)

	okA, err := rbac.CanAccessClient(f.ctx, u.ID, clientA.ID)
	require.NoError(t, err)
	require.True(t, okA)

	require.NoError(t, rbac.Authorize(f.ctx, service.AuthorizeInput{
		RealmID: f.realm.ID, UserID: u.ID, ClientRef: clientA.ID, Resource: "client", Action: "read",
	}))

	// Client B: same user, same role, nothing.
	permsB, err := rbac.GetEffectivePermissions(f.ctx, u.ID, clientB.ID)
	require.NoError(t, err)
	require.Empty(t, permsB)

	okB, err := rbac.CanAccessClient(f.ctx, u.ID, clientB.ID)
	require.NoError(t, err)
	require.False(t, okB)

	err = rbac.Authorize(f.ctx, service.AuthorizeInput{
		RealmID: f.realm.ID, UserID: u.ID, ClientRef: clientB.ID, Resource: "client", Action: "read",
		IPAddress: "203.0.113.7", UserAgent: "rbac-integration-test",
	})
	require.ErrorIs(t, err, service.ErrForbidden)

	// The refusal (and only the refusal) is in the AuditLog.
	logs, err := entstore.NewAuditLogRepository(f.client).ListByUser(f.ctx, u.ID)
	require.NoError(t, err)

	var denials []*domain.AuditLog
	for _, l := range logs {
		if l.Action == "authorization_denied" {
			denials = append(denials, l)
		}
	}
	require.Len(t, denials, 1)
	d := denials[0]
	require.Equal(t, f.realm.ID, d.RealmID)
	require.Equal(t, domain.AuditLogFailure, d.Status)
	require.Equal(t, domain.AuditLogWarning, d.Level)
	require.Equal(t, "ClientApp", d.ResourceType)
	require.Equal(t, clientB.ID, d.ResourceID)
	require.Equal(t, "203.0.113.7", d.IPAddress)
	require.Equal(t, "no_access_to_client", d.Details["reason"])
}

// DoD 2: a scope granted by the user's group is present even though the
// user's direct role grants no scope at all (confirms there is no "deny").
func TestRBAC_GroupScopeNotRemovedByRole_Integration(t *testing.T) {
	f := newRBACFixture(t)
	rbac := f.rbacService()

	u := f.user()
	g := f.group()
	r := f.role() // grants no scope
	groupsScope := f.clientScope("groups")
	clientA := f.clientApp("client-a")

	f.addToGroup(u, g)
	f.assignRole(u, r)
	f.grantScopeToGroup(g, groupsScope)
	f.allowGroupOnClient(clientA, g)
	f.allowRoleOnClient(clientA, r)
	f.mapScopeToClient(clientA, groupsScope)

	scopes, err := rbac.GetEffectiveClientScopes(f.ctx, u.ID, clientA.ID)
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	require.Equal(t, groupsScope.ID, scopes[0].ID)
}

func TestAccessRepository_NotFound_Integration(t *testing.T) {
	f := newRBACFixture(t)
	repo := entstore.NewAccessRepository(f.client)

	_, err := repo.GetUserAccess(f.ctx, uuid.NewString())
	require.ErrorIs(t, err, repository.ErrNotFound)

	_, err = repo.GetClientAccessPolicy(f.ctx, uuid.NewString())
	require.ErrorIs(t, err, repository.ErrNotFound)
}
