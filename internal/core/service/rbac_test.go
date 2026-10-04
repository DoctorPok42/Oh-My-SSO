package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// --- in-memory fakes -------------------------------------------------------

type fakeAccessRepo struct {
	users   map[string]*domain.UserAccess
	clients map[string]*domain.ClientAccessPolicy
	err     error // when set, every call fails with this technical error
}

func (f *fakeAccessRepo) GetUserAccess(_ context.Context, userID string) (*domain.UserAccess, error) {
	if f.err != nil {
		return nil, f.err
	}
	u, ok := f.users[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return u, nil
}

func (f *fakeAccessRepo) GetClientAccessPolicy(_ context.Context, clientRef string) (*domain.ClientAccessPolicy, error) {
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.clients[clientRef]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return c, nil
}

type fakeAuditRepo struct {
	mu      sync.Mutex
	entries []repository.CreateAuditLogParams
	err     error
}

func (f *fakeAuditRepo) Create(_ context.Context, p repository.CreateAuditLogParams) (*domain.AuditLog, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.entries = append(f.entries, p)
	return &domain.AuditLog{RealmID: p.RealmID, Action: p.Action}, nil
}

func (f *fakeAuditRepo) GetByID(context.Context, string) (*domain.AuditLog, error) {
	return nil, repository.ErrNotFound
}

func (f *fakeAuditRepo) ListByResource(context.Context, string, string) ([]*domain.AuditLog, error) {
	return nil, nil
}

func (f *fakeAuditRepo) ListByUser(context.Context, string) ([]*domain.AuditLog, error) {
	return nil, nil
}

func (f *fakeAuditRepo) ListByRealm(context.Context, string) ([]*domain.AuditLog, error) {
	return nil, nil
}

// --- fixture builders ------------------------------------------------------

const realmA = "realm-a"

func perm(id, resource, action string) *domain.Permission {
	return &domain.Permission{
		ID: id, RealmID: realmA, Name: resource + ":" + action,
		Resource: resource, Action: action, Status: domain.PermissionActive,
	}
}

func scope(id, name string) *domain.ClientScope {
	return &domain.ClientScope{ID: id, RealmID: realmA, Name: name}
}

func role(id string, perms []*domain.Permission, scopes []*domain.ClientScope) domain.AccessSource {
	return domain.AccessSource{
		Kind: domain.AccessSourceRole, ID: id, RealmID: realmA, Name: id, Active: true,
		Permissions: perms, ClientScopes: scopes,
	}
}

func group(id string, perms []*domain.Permission, scopes []*domain.ClientScope) domain.AccessSource {
	src := role(id, perms, scopes)
	src.Kind = domain.AccessSourceGroup
	return src
}

func activeUser(id string, roles, groups []domain.AccessSource) *domain.UserAccess {
	return &domain.UserAccess{UserID: id, RealmID: realmA, Status: domain.UserActive, Roles: roles, Groups: groups}
}

func activeClient(ref string, roleIDs, groupIDs, scopeIDs []string) *domain.ClientAccessPolicy {
	return &domain.ClientAccessPolicy{
		ClientRef: ref, RealmID: realmA, Status: domain.ClientAppActive,
		RoleIDs: roleIDs, GroupIDs: groupIDs, ScopeIDs: scopeIDs,
	}
}

func newRBAC(access *fakeAccessRepo) (*service.RBACService, *fakeAuditRepo) {
	audit := &fakeAuditRepo{}
	return service.NewRBACService(access, audit), audit
}

func permNames(ps []*domain.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func scopeNames(cs []*domain.ClientScope) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// --- tests -----------------------------------------------------------------

func TestRBAC_GetEffectivePermissions(t *testing.T) {
	read := perm("p-read", "client", "read")
	create := perm("p-create", "client", "create")
	inactive := perm("p-old", "key", "rotate")
	inactive.Status = domain.PermissionInactive
	otherRealm := perm("p-foreign", "user", "delete")
	otherRealm.RealmID = "realm-b"

	disabledRole := role("r-disabled", []*domain.Permission{create}, nil)
	disabledRole.Active = false

	foreignRole := role("r-foreign", []*domain.Permission{create}, nil)
	foreignRole.RealmID = "realm-b"

	tests := []struct {
		name   string
		user   *domain.UserAccess
		client *domain.ClientAccessPolicy
		want   []string
	}{
		{
			name:   "union of role and group, deduplicated",
			user:   activeUser("u", []domain.AccessSource{role("r1", []*domain.Permission{read, create}, nil)}, []domain.AccessSource{group("g1", []*domain.Permission{read}, nil)}),
			client: activeClient("c", []string{"r1"}, []string{"g1"}, nil),
			want:   []string{"client:create", "client:read"},
		},
		{
			name:   "role not allowed on the client brings nothing",
			user:   activeUser("u", []domain.AccessSource{role("r1", []*domain.Permission{create}, nil)}, []domain.AccessSource{group("g1", []*domain.Permission{read}, nil)}),
			client: activeClient("c", nil, []string{"g1"}, nil),
			want:   []string{"client:read"},
		},
		{
			name:   "inactive role is ignored",
			user:   activeUser("u", []domain.AccessSource{disabledRole}, []domain.AccessSource{group("g1", []*domain.Permission{read}, nil)}),
			client: activeClient("c", []string{"r-disabled"}, []string{"g1"}, nil),
			want:   []string{"client:read"},
		},
		{
			name:   "inactive or foreign-realm permission is ignored",
			user:   activeUser("u", []domain.AccessSource{role("r1", []*domain.Permission{read, inactive, otherRealm}, nil)}, nil),
			client: activeClient("c", []string{"r1"}, nil, nil),
			want:   []string{"client:read"},
		},
		{
			name:   "role from another realm is ignored",
			user:   activeUser("u", []domain.AccessSource{foreignRole}, nil),
			client: activeClient("c", []string{"r-foreign"}, nil, nil),
			want:   []string{},
		},
		{
			name:   "client without ClientRole/ClientGroup is closed to everyone",
			user:   activeUser("u", []domain.AccessSource{role("r1", []*domain.Permission{read}, nil)}, nil),
			client: activeClient("c", nil, nil, nil),
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbac, _ := newRBAC(&fakeAccessRepo{
				users:   map[string]*domain.UserAccess{"u": tt.user},
				clients: map[string]*domain.ClientAccessPolicy{"c": tt.client},
			})
			got, err := rbac.GetEffectivePermissions(context.Background(), "u", "c")
			require.NoError(t, err)
			require.Equal(t, tt.want, permNames(got))
		})
	}
}

func TestRBAC_Guards(t *testing.T) {
	read := perm("p-read", "client", "read")
	r1 := role("r1", []*domain.Permission{read}, nil)

	suspended := activeUser("u", []domain.AccessSource{r1}, nil)
	suspended.Status = domain.UserSuspended

	inactiveClient := activeClient("c", []string{"r1"}, nil, nil)
	inactiveClient.Status = domain.ClientAppInactive

	foreignClient := activeClient("c", []string{"r1"}, nil, nil)
	foreignClient.RealmID = "realm-b"

	tests := []struct {
		name       string
		user       *domain.UserAccess
		client     *domain.ClientAccessPolicy
		wantReason string
	}{
		{"suspended user", suspended, activeClient("c", []string{"r1"}, nil, nil), "user_not_active"},
		{"inactive client", activeUser("u", []domain.AccessSource{r1}, nil), inactiveClient, "client_not_active"},
		{"client of another realm", activeUser("u", []domain.AccessSource{r1}, nil), foreignClient, "realm_mismatch"},
		{"unknown user", nil, activeClient("c", []string{"r1"}, nil, nil), "user_not_found"},
		{"unknown client", activeUser("u", []domain.AccessSource{r1}, nil), nil, "client_not_found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeAccessRepo{users: map[string]*domain.UserAccess{}, clients: map[string]*domain.ClientAccessPolicy{}}
			if tt.user != nil {
				repo.users["u"] = tt.user
			}
			if tt.client != nil {
				repo.clients["c"] = tt.client
			}
			rbac, audit := newRBAC(repo)
			ctx := context.Background()

			ok, err := rbac.CanAccessClient(ctx, "u", "c")
			require.NoError(t, err)
			require.False(t, ok)

			perms, err := rbac.GetEffectivePermissions(ctx, "u", "c")
			require.NoError(t, err)
			require.Empty(t, perms)

			err = rbac.Authorize(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", ClientRef: "c", Resource: "client", Action: "read"})
			require.ErrorIs(t, err, service.ErrForbidden)
			require.Len(t, audit.entries, 1)
			require.Equal(t, tt.wantReason, audit.entries[0].Details["reason"])
		})
	}
}

func TestRBAC_GetEffectiveClientScopes(t *testing.T) {
	groups := scope("s-groups", "groups")
	empID := scope("s-emp", "internal-employee-id")
	notMapped := scope("s-secret", "secret-claim")

	t.Run("scope from group is kept even if the direct role grants none (no deny)", func(t *testing.T) {
		rbac, _ := newRBAC(&fakeAccessRepo{
			users: map[string]*domain.UserAccess{"u": activeUser("u",
				[]domain.AccessSource{role("r1", nil, nil)},
				[]domain.AccessSource{group("g1", nil, []*domain.ClientScope{groups})})},
			clients: map[string]*domain.ClientAccessPolicy{"c": activeClient("c", []string{"r1"}, []string{"g1"}, []string{"s-groups"})},
		})
		got, err := rbac.GetEffectiveClientScopes(context.Background(), "u", "c")
		require.NoError(t, err)
		require.Equal(t, []string{"groups"}, scopeNames(got))
	})

	t.Run("union, deduplicated, restricted to ClientScopeMapping", func(t *testing.T) {
		rbac, _ := newRBAC(&fakeAccessRepo{
			users: map[string]*domain.UserAccess{"u": activeUser("u",
				[]domain.AccessSource{role("r1", nil, []*domain.ClientScope{groups, empID})},
				[]domain.AccessSource{group("g1", nil, []*domain.ClientScope{groups, notMapped})})},
			clients: map[string]*domain.ClientAccessPolicy{"c": activeClient("c", []string{"r1"}, []string{"g1"}, []string{"s-groups", "s-emp"})},
		})
		got, err := rbac.GetEffectiveClientScopes(context.Background(), "u", "c")
		require.NoError(t, err)
		require.Equal(t, []string{"groups", "internal-employee-id"}, scopeNames(got))
	})

	t.Run("no access to the client means no scopes", func(t *testing.T) {
		rbac, _ := newRBAC(&fakeAccessRepo{
			users: map[string]*domain.UserAccess{"u": activeUser("u", nil,
				[]domain.AccessSource{group("g1", nil, []*domain.ClientScope{groups})})},
			clients: map[string]*domain.ClientAccessPolicy{"c": activeClient("c", nil, nil, []string{"s-groups"})},
		})
		got, err := rbac.GetEffectiveClientScopes(context.Background(), "u", "c")
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestRBAC_Authorize(t *testing.T) {
	read := perm("p-read", "client", "read")
	repo := &fakeAccessRepo{
		users:   map[string]*domain.UserAccess{"u": activeUser("u", []domain.AccessSource{role("r1", []*domain.Permission{read}, nil)}, nil)},
		clients: map[string]*domain.ClientAccessPolicy{"c": activeClient("c", []string{"r1"}, nil, nil)},
	}
	ctx := context.Background()

	t.Run("matching permission is allowed and not audited", func(t *testing.T) {
		rbac, audit := newRBAC(repo)
		err := rbac.Authorize(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", ClientRef: "c", Resource: "client", Action: "read"})
		require.NoError(t, err)
		require.Empty(t, audit.entries)
	})

	t.Run("missing permission is refused and audited with details", func(t *testing.T) {
		rbac, audit := newRBAC(repo)
		err := rbac.Authorize(ctx, service.AuthorizeInput{
			RealmID: realmA, UserID: "u", ClientRef: "c", Resource: "client", Action: "delete",
			IPAddress: "203.0.113.7", UserAgent: "test-agent",
		})
		require.ErrorIs(t, err, service.ErrForbidden)
		require.Len(t, audit.entries, 1)

		e := audit.entries[0]
		require.Equal(t, "authorization_denied", e.Action)
		require.Equal(t, domain.AuditLogFailure, e.Status)
		require.Equal(t, domain.AuditLogWarning, e.Level)
		require.Equal(t, "ClientApp", e.ResourceType)
		require.Equal(t, "c", e.ResourceID)
		require.Equal(t, "203.0.113.7", e.IPAddress)
		require.Equal(t, "missing_permission", e.Details["reason"])
		require.Equal(t, "client", e.Details["resource"])
		require.Equal(t, "delete", e.Details["action"])
	})

	t.Run("empty client ref is refused without hitting the repository", func(t *testing.T) {
		rbac, audit := newRBAC(&fakeAccessRepo{err: errors.New("must not be called")})
		err := rbac.Authorize(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", Resource: "client", Action: "read"})
		require.ErrorIs(t, err, service.ErrForbidden)
		require.Equal(t, "client_not_found", audit.entries[0].Details["reason"])
	})

	t.Run("audit failure still refuses (fail closed)", func(t *testing.T) {
		audit := &fakeAuditRepo{err: errors.New("audit down")}
		rbac := service.NewRBACService(repo, audit)
		err := rbac.Authorize(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", ClientRef: "c", Resource: "client", Action: "delete"})
		require.ErrorIs(t, err, service.ErrForbidden)
	})

	t.Run("technical error is not a refusal and is not audited", func(t *testing.T) {
		audit := &fakeAuditRepo{}
		rbac := service.NewRBACService(&fakeAccessRepo{err: errors.New("db down")}, audit)
		err := rbac.Authorize(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", ClientRef: "c", Resource: "client", Action: "read"})
		require.Error(t, err)
		require.NotErrorIs(t, err, service.ErrForbidden)
		require.Empty(t, audit.entries)
	})

	t.Run("AuthorizeClientAccess audits refusals", func(t *testing.T) {
		rbac, audit := newRBAC(repo)
		require.NoError(t, rbac.AuthorizeClientAccess(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", ClientRef: "c"}))
		err := rbac.AuthorizeClientAccess(ctx, service.AuthorizeInput{RealmID: realmA, UserID: "u", ClientRef: "unknown"})
		require.ErrorIs(t, err, service.ErrForbidden)
		require.Len(t, audit.entries, 1)
		require.Equal(t, "client_not_found", audit.entries[0].Details["reason"])
		_, hasResource := audit.entries[0].Details["resource"]
		require.False(t, hasResource)
	})
}
