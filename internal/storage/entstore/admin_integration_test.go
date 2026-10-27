package entstore_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestAdminRepository_Integration(t *testing.T) {
	f := newRBACFixture(t)
	admin := entstore.NewAdminRepository(f.client)
	access := entstore.NewAccessRepository(f.client)
	ctx := f.ctx

	alice, bob := f.user(), f.user()
	staff, ops := f.group(), f.group()
	support := f.role()
	app := f.clientApp("payroll")
	groupsScope, deptScope := f.clientScope("groups"), f.clientScope("dept")

	t.Run("memberships are replaced as a whole", func(t *testing.T) {
		require.NoError(t, admin.SetUserGroups(ctx, alice.ID, []string{staff.ID, ops.ID}))
		require.NoError(t, admin.SetUserRoles(ctx, alice.ID, []string{support.ID}))
		require.NoError(t, admin.SetUserGroups(ctx, bob.ID, []string{staff.ID}))
		require.NoError(t, admin.SetUserGroups(ctx, alice.ID, []string{ops.ID}))

		m, err := admin.Memberships(ctx, []string{alice.ID, bob.ID})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{ops.ID}, m[alice.ID].GroupIDs)
		require.ElementsMatch(t, []string{support.ID}, m[alice.ID].RoleIDs)
		require.ElementsMatch(t, []string{staff.ID}, m[bob.ID].GroupIDs)
		require.Equal(t, map[string]string{ops.ID: ops.Name, support.ID: support.Name}, m[alice.ID].Names,
			"names come with the memberships")

		// Counted by PostgreSQL; a deleted account does not count.
		carol := f.user()
		require.NoError(t, admin.SetUserGroups(ctx, carol.ID, []string{staff.ID}))
		require.NoError(t, f.client.User.UpdateOneID(carol.ID).SetDeletedAt(time.Now()).Exec(ctx))
		groups, err := admin.GroupMemberCounts(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Equal(t, 1, groups[staff.ID])
		require.Equal(t, 1, groups[ops.ID])
		roles, err := admin.RoleMemberCounts(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Equal(t, map[string]int{support.ID: 1}, roles)

		ids, err := admin.ActiveGroupMemberIDs(ctx, staff.ID)
		require.NoError(t, err)
		require.Equal(t, []string{bob.ID}, ids)
	})

	t.Run("search users", func(t *testing.T) {
		got, total, err := admin.SearchUsers(ctx, repository.UserSearch{RealmID: f.realm.ID, GroupID: ops.ID})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Equal(t, alice.ID, got[0].ID)

		_, total, err = admin.SearchUsers(ctx, repository.UserSearch{RealmID: f.realm.ID, Query: "USER-"})
		require.NoError(t, err)
		require.Equal(t, 2, total, "case-insensitive: both usernames start with user-")

		_, total, err = admin.SearchUsers(ctx, repository.UserSearch{RealmID: f.realm.ID, Page: repository.Page{Limit: 1}})
		require.NoError(t, err)
		require.Equal(t, 2, total, "total ignores the page size")

		// The total without a COUNT query (page not full), with one (full
		// page, or empty page past the end), or not at all.
		for _, c := range []struct {
			page  repository.Page
			rows  int
			total int
		}{
			{repository.Page{Limit: 10}, 2, 2},
			{repository.Page{Offset: 1, Limit: 10}, 1, 2},
			{repository.Page{Offset: 1, Limit: 1}, 1, 2},
			{repository.Page{Offset: 5, Limit: 10}, 0, 2},
			{repository.Page{Limit: 10, NoTotal: true}, 2, -1},
		} {
			got, total, err := admin.SearchUsers(ctx, repository.UserSearch{RealmID: f.realm.ID, Page: c.page})
			require.NoError(t, err)
			require.Len(t, got, c.rows, "%+v", c.page)
			require.Equal(t, c.total, total, "%+v", c.page)
		}

		n, err := admin.CountUsersWithPassword(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("client grants, and required scopes reach the access policy", func(t *testing.T) {
		require.NoError(t, admin.SetClientGroups(ctx, app.ID, []string{staff.ID, ops.ID}, "user:admin"))
		require.NoError(t, admin.SetClientGroups(ctx, app.ID, []string{ops.ID}, "user:admin"))
		require.NoError(t, admin.SetClientRoles(ctx, app.ID, []string{support.ID}, "user:admin"))
		require.NoError(t, admin.SetClientScopes(ctx, app.ID, []repository.ScopeMapping{
			{ClientScopeID: groupsScope.ID, Required: true}, {ClientScopeID: deptScope.ID},
		}))

		g, err := admin.ClientGrants(ctx, app.ID)
		require.NoError(t, err)
		require.Equal(t, []string{ops.ID}, g.GroupIDs)
		require.Equal(t, []string{support.ID}, g.RoleIDs)
		require.ElementsMatch(t, []repository.ScopeMapping{
			{ClientScopeID: groupsScope.ID, Required: true, Name: groupsScope.Name, Protocol: string(groupsScope.Protocol)},
			{ClientScopeID: deptScope.ID, Name: deptScope.Name, Protocol: string(deptScope.Protocol)},
		}, g.Scopes, "the scopes' names come with the mappings")
		require.Equal(t, map[string]string{ops.ID: ops.Name, support.ID: support.Name}, g.Names)

		policy, err := access.GetClientAccessPolicy(ctx, app.ID)
		require.NoError(t, err)
		require.Equal(t, []string{groupsScope.ID}, policy.RequiredScopeIDs)

		// Flip the flags: updated in place.
		require.NoError(t, admin.SetClientScopes(ctx, app.ID, []repository.ScopeMapping{{ClientScopeID: deptScope.ID, Required: true}}))
		policy, err = access.GetClientAccessPolicy(ctx, app.ID)
		require.NoError(t, err)
		require.Equal(t, []string{deptScope.ID}, policy.RequiredScopeIDs)
		require.Equal(t, []string{deptScope.ID}, policy.ScopeIDs)

		usage, err := admin.ScopeUsage(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Equal(t, 1, usage[deptScope.ID])
		require.Zero(t, usage[groupsScope.ID])
	})

	t.Run("role and group grants", func(t *testing.T) {
		p1, p2 := f.permission("invoice", "read"), f.permission("invoice", "approve")
		require.NoError(t, admin.SetRolePermissions(ctx, support.ID, []string{p1.ID, p2.ID}))
		require.NoError(t, admin.SetRoleClientScopes(ctx, support.ID, []string{groupsScope.ID}))
		require.NoError(t, admin.SetGroupPermissions(ctx, ops.ID, []string{p2.ID}))
		require.NoError(t, admin.SetRolePermissions(ctx, support.ID, []string{p1.ID}))

		rg, err := admin.RoleGrants(ctx, support.ID)
		require.NoError(t, err)
		require.Equal(t, []string{p1.ID}, rg.PermissionIDs)
		require.Equal(t, []string{groupsScope.ID}, rg.ClientScopeIDs)
		gg, err := admin.GroupGrants(ctx, ops.ID)
		require.NoError(t, err)
		require.Equal(t, []string{p2.ID}, gg.PermissionIDs)

		// Every role / group of the realm at once.
		all, err := admin.RealmRoleGrants(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Equal(t, rg, all[support.ID])
		allGroups, err := admin.RealmGroupGrants(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Equal(t, gg, allGroups[ops.ID])
		require.Equal(t, repository.Grants{PermissionIDs: []string{}, ClientScopeIDs: []string{}}, allGroups[staff.ID])

		require.NoError(t, admin.SetManagedBy(ctx, "group", ops.ID, "config"))
		g, err := entstore.NewGroupRepository(f.client).GetByID(ctx, ops.ID)
		require.NoError(t, err)
		require.Equal(t, domain.GroupManagedByConfig, g.ManagedBy)
	})

	t.Run("sign-ins per realm and per user", func(t *testing.T) {
		attempts := entstore.NewLoginAttemptRepository(f.client)
		for _, st := range []domain.LoginAttemptStatus{domain.LoginAttemptSuccess, domain.LoginAttemptFailure, domain.LoginAttemptSuccess} {
			_, err := attempts.Create(ctx, repository.CreateLoginAttemptParams{RealmID: f.realm.ID, UserID: alice.ID,
				Identifier: alice.Username, Status: st})
			require.NoError(t, err)
		}
		ok, ko, err := admin.LoginCounts(ctx, f.realm.ID, time.Now().Add(-time.Hour))
		require.NoError(t, err)
		require.Equal(t, 2, ok)
		require.Equal(t, 1, ko)

		last, err := admin.LastSuccessfulLogins(ctx, []string{alice.ID, bob.ID})
		require.NoError(t, err)
		require.WithinDuration(t, time.Now(), last[alice.ID], time.Minute)
		_, ok2 := last[bob.ID]
		require.False(t, ok2)

		mine, err := admin.LoginAttemptsByUser(ctx, alice.ID, 10)
		require.NoError(t, err)
		require.Len(t, mine, 3)
		require.Equal(t, f.realm.ID, mine[0].RealmID)
	})

	t.Run("MFA coverage counts real factors only", func(t *testing.T) {
		methods := entstore.NewMfaMethodRepository(f.client)
		_, err := methods.Create(ctx, repository.CreateMfaMethodParams{UserID: alice.ID, Type: domain.MfaMethodPasskey,
			Status: domain.MfaMethodActive, CredentialID: "cred-" + alice.ID})
		require.NoError(t, err)
		_, err = methods.Create(ctx, repository.CreateMfaMethodParams{UserID: bob.ID, Type: domain.MfaMethodBackupCodes,
			Status: domain.MfaMethodActive})
		require.NoError(t, err)

		enrolled, total, err := admin.MFACoverage(ctx, f.realm.ID)
		require.NoError(t, err)
		require.Equal(t, 1, enrolled)
		require.Equal(t, 2, total)
		has, err := admin.UsersWithActiveMFA(ctx, []string{alice.ID, bob.ID})
		require.NoError(t, err)
		require.True(t, has[alice.ID])
		require.False(t, has[bob.ID])
	})

	t.Run("audit search", func(t *testing.T) {
		audit := entstore.NewAuditLogRepository(f.client)
		for _, p := range []repository.CreateAuditLogParams{
			{RealmID: f.realm.ID, UserID: "admin-1", Action: "admin.user.update", ResourceType: "User", ResourceID: alice.ID},
			{RealmID: f.realm.ID, UserID: alice.ID, Action: "login", Status: domain.AuditLogFailure, Level: domain.AuditLogWarning},
			{RealmID: f.realm.ID, UserID: "admin-1", Action: "admin.client.update", ResourceType: "ClientApp", ResourceID: app.ID},
		} {
			if p.Status == "" {
				p.Status = domain.AuditLogSuccess
			}
			if p.Level == "" {
				p.Level = domain.AuditLogInfo
			}
			_, err := audit.Create(ctx, p)
			require.NoError(t, err)
		}
		_, total, err := admin.SearchAuditLogs(ctx, repository.AuditSearch{RealmID: f.realm.ID, UserID: alice.ID})
		require.NoError(t, err)
		require.Equal(t, 2, total, "done by alice, or about alice")
		_, total, err = admin.SearchAuditLogs(ctx, repository.AuditSearch{RealmID: f.realm.ID, ClientRef: app.ID})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		_, total, err = admin.SearchAuditLogs(ctx, repository.AuditSearch{RealmID: f.realm.ID, Status: domain.AuditLogFailure})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		rows, total, err := admin.SearchAuditLogs(ctx, repository.AuditSearch{RealmID: f.realm.ID,
			Levels: []domain.AuditLogLevel{domain.AuditLogWarning, domain.AuditLogError}})
		require.NoError(t, err)
		require.Equal(t, 1, total, "the bell: warning and above only")
		require.Equal(t, "login", rows[0].Action)
		_, total, err = admin.SearchAuditLogs(ctx, repository.AuditSearch{RealmID: f.realm.ID, From: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		require.Zero(t, total)
	})

	t.Run("sessions: count alone", func(t *testing.T) {
		sessions := entstore.NewSessionRepository(f.client)
		for _, u := range []*domain.User{alice, alice, bob} {
			_, err := sessions.Create(ctx, repository.CreateSessionParams{RealmID: f.realm.ID, UserID: u.ID,
				TokenHash: "hash-" + u.ID + time.Now().String(), ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword})
			require.NoError(t, err)
		}
		live := repository.SessionSearch{RealmID: f.realm.ID, Now: time.Now(), IdleSince: time.Now().Add(-time.Hour)}
		n, err := admin.CountSessions(ctx, live)
		require.NoError(t, err)
		require.Equal(t, 3, n)
		live.UserID = alice.ID
		n, err = admin.CountSessions(ctx, live)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		rows, total, err := admin.SearchSessions(ctx, repository.SessionSearch{RealmID: f.realm.ID, Now: time.Now(),
			IdleSince: time.Now().Add(-time.Hour), Page: repository.Page{Limit: 2}})
		require.NoError(t, err)
		require.Len(t, rows, 2)
		require.Equal(t, 3, total)
	})

	t.Run("sessions: remembered ones follow their own idle timeout", func(t *testing.T) {
		realm := newTestRealm(t, ctx, f.client)
		sessions := entstore.NewSessionRepository(f.client)
		now := time.Now()
		create := func(created time.Time, remember bool) *domain.Session {
			s, err := sessions.Create(ctx, repository.CreateSessionParams{RealmID: realm.ID, UserID: alice.ID,
				TokenHash: "hash-" + uuid.NewString(), CreatedAt: created, ExpiresAt: now.Add(24 * time.Hour),
				AuthMethod: domain.AuthMethodPassword, RememberMe: remember})
			require.NoError(t, err)
			return s
		}
		create(now.Add(-time.Hour), false)          // normal, idle for an hour: gone
		create(now.Add(-48*time.Hour), true)        // remembered, idle for two days
		busy := create(now.Add(-9*time.Hour), true) // remembered, 9 hours old, just used
		require.NoError(t, sessions.Touch(ctx, busy.ID, now.Add(-time.Minute)))

		on := repository.SessionSearch{RealmID: realm.ID, Now: now, IdleSince: now.Add(-10 * time.Minute),
			RememberIdleSince: now.Add(-7 * 24 * time.Hour)}
		rows, total, err := admin.SearchSessions(ctx, on)
		require.NoError(t, err)
		require.Equal(t, 2, total)
		for _, r := range rows {
			require.True(t, r.RememberMe)
		}

		// The realm turned the option off: normal idle timeout and lifetime.
		off := repository.SessionSearch{RealmID: realm.ID, Now: now, IdleSince: now.Add(-10 * time.Minute),
			RememberIdleSince: now.Add(-10 * time.Minute), RememberCreatedSince: now.Add(-8 * time.Hour)}
		n, err := admin.CountSessions(ctx, off)
		require.NoError(t, err)
		require.Zero(t, n)
		create(now, true)
		n, err = admin.CountSessions(ctx, off)
		require.NoError(t, err)
		require.Equal(t, 1, n)
	})

	t.Run("the master realm is created only here", func(t *testing.T) {
		_, err := entstore.NewRealmRepository(f.client).Create(ctx, repository.CreateRealmParams{Name: "master"})
		require.ErrorIs(t, err, repository.ErrReservedRealmName)
		realms, err := admin.ListRealms(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, realms)
	})
}
