package entstore

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/ent/clientapp"
	"sso.internal/sso/ent/clientgroup"
	"sso.internal/sso/ent/clientrole"
	"sso.internal/sso/ent/clientscope"
	"sso.internal/sso/ent/clientscopemapping"
	"sso.internal/sso/ent/group"
	"sso.internal/sso/ent/loginattempt"
	"sso.internal/sso/ent/mfamethod"
	"sso.internal/sso/ent/permission"
	"sso.internal/sso/ent/predicate"
	"sso.internal/sso/ent/realm"
	"sso.internal/sso/ent/role"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/session"
	"sso.internal/sso/ent/timeout"
	"sso.internal/sso/ent/token"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


type entAdminRepository struct {
	client *ent.Client
}

func NewAdminRepository(client *ent.Client) repository.AdminRepository {
	return &entAdminRepository{client: client}
}

// maxPageSize caps every list, whatever the caller asks for.
const maxPageSize = 200

func clampPage(p repository.Page) (offset, limit int) {
	offset, limit = p.Offset, p.Limit
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > maxPageSize {
		limit = maxPageSize
	}
	return offset, limit
}

// pageTotal returns the total number of matches of a paged search. The page
// is read first: when it is not full, it tells the total by itself (offset +
// rows) and the COUNT query is skipped. A small realm's lists thus cost one
// query instead of two. Only an empty page after the first one (the total
// shrank) or a full page needs counting.
func pageTotal(ctx context.Context, p repository.Page, offset, limit, got int, count func(context.Context) (int, error)) (int, error) {
	switch {
	case p.NoTotal:
		return -1, nil
	case got < limit && (got > 0 || offset == 0):
		return offset + got, nil
	}
	return count(ctx)
}

// quoteIdent quotes a PostgreSQL identifier ("user_groups"). For the
// hand-written sub-queries below, built only from Ent's table and column
// constants, never from input.
func quoteIdent(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

// quoteLiteral quotes a constant of this code ('active') for the same
// sub-queries: an aggregate expression cannot carry bind parameters.
func quoteLiteral(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

// --- realms ---------------------------------------------------------------------

func (r *entAdminRepository) ListRealms(ctx context.Context) ([]*domain.Realm, error) {
	rows, err := r.client.Realm.Query().Order(ent.Desc(realm.FieldIsSystemRealm), ent.Asc(realm.FieldName)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Realm, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainRealm(e))
	}
	return out, nil
}

func (r *entAdminRepository) CreateSystemRealm(ctx context.Context, p repository.CreateRealmParams) (*domain.Realm, error) {
	e, err := r.client.Realm.Create().
		SetName(p.Name).
		SetIsSystemRealm(true).
		SetNillableDisplayName(nonEmpty(p.DisplayName)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainRealm(e), nil
}

// --- users ----------------------------------------------------------------------

func (r *entAdminRepository) SearchUsers(ctx context.Context, f repository.UserSearch) ([]*domain.User, int, error) {
	preds := []predicate.User{user.RealmID(f.RealmID), user.DeletedAtIsNil()}
	if f.Query != "" {
		preds = append(preds, user.Or(user.UsernameContainsFold(f.Query), user.EmailContainsFold(f.Query)))
	}
	if f.Status != "" {
		preds = append(preds, user.StatusEQ(entschema.UserStatus(f.Status)))
	}
	if f.GroupID != "" {
		preds = append(preds, user.HasGroupsWith(group.ID(f.GroupID)))
	}
	if f.RoleID != "" {
		preds = append(preds, user.HasRolesWith(role.ID(f.RoleID)))
	}
	q := r.client.User.Query().Where(preds...)
	offset, limit := clampPage(f.Page)
	rows, err := q.Clone().Order(ent.Asc(user.FieldUsername)).Offset(offset).Limit(limit).All(ctx)
	if err != nil {
		return nil, 0, err
	}
	total, err := pageTotal(ctx, f.Page, offset, limit, len(rows), q.Count)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*domain.User, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainUser(e))
	}
	return out, total, nil
}

func (r *entAdminRepository) UsersByIDs(ctx context.Context, ids []string) ([]*domain.User, error) {
	if len(ids) == 0 {
		return []*domain.User{}, nil
	}
	rows, err := r.client.User.Query().Where(user.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.User, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainUser(e))
	}
	return out, nil
}

func (r *entAdminRepository) SetUserProfile(ctx context.Context, userID string, profile map[string]interface{}) error {
	return mapNotFound(r.client.User.UpdateOneID(userID).SetProfile(profile).Exec(ctx))
}

func (r *entAdminRepository) CountUsersWithPassword(ctx context.Context, realmID string) (int, error) {
	return r.client.User.Query().
		Where(user.RealmID(realmID), user.PasswordHashNotNil(), user.PasswordHashNEQ("")).
		Count(ctx)
}

func (r *entAdminRepository) Memberships(ctx context.Context, userIDs []string) (map[string]repository.Memberships, error) {
	out := make(map[string]repository.Memberships, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := r.client.User.Query().
		Where(user.IDIn(userIDs...)).
		Select(user.FieldID).
		WithGroups(func(q *ent.GroupQuery) { q.Select(group.FieldID, group.FieldName) }).
		WithRoles(func(q *ent.RoleQuery) { q.Select(role.FieldID, role.FieldName) }).
		All(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range rows {
		m := repository.Memberships{GroupIDs: []string{}, RoleIDs: []string{}, Names: map[string]string{}}
		for _, g := range u.Edges.Groups {
			m.GroupIDs = append(m.GroupIDs, g.ID)
			m.Names[g.ID] = g.Name
		}
		for _, ro := range u.Edges.Roles {
			m.RoleIDs = append(m.RoleIDs, ro.ID)
			m.Names[ro.ID] = ro.Name
		}
		out[u.ID] = m
	}
	return out, nil
}

func (r *entAdminRepository) SetUserGroups(ctx context.Context, userID string, groupIDs []string) error {
	return mapNotFound(r.client.User.UpdateOneID(userID).ClearGroups().AddGroupIDs(groupIDs...).Exec(ctx))
}

func (r *entAdminRepository) SetUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	return mapNotFound(r.client.User.UpdateOneID(userID).ClearRoles().AddRoleIDs(roleIDs...).Exec(ctx))
}

func (r *entAdminRepository) ActiveGroupMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	return r.client.Group.Query().
		Where(group.ID(groupID)).
		QueryUsers().
		Where(user.StatusEQ(entschema.UserActive), user.DeletedAtIsNil()).
		IDs(ctx)
}

func (r *entAdminRepository) GroupMemberCounts(ctx context.Context, realmID string) (map[string]int, error) {
	var rows []struct {
		ID      string `json:"id"`
		Members int    `json:"members"`
	}
	err := r.client.Group.Query().Where(group.RealmID(realmID)).
		Select(group.FieldID).
		Aggregate(memberCount(group.UsersTable, group.UsersPrimaryKey[1])).
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(rows))
	for _, row := range rows {
		out[row.ID] = row.Members
	}
	return out, nil
}

func (r *entAdminRepository) RoleMemberCounts(ctx context.Context, realmID string) (map[string]int, error) {
	var rows []struct {
		ID      string `json:"id"`
		Members int    `json:"members"`
	}
	err := r.client.Role.Query().Where(role.RealmID(realmID)).
		Select(role.FieldID).
		Aggregate(memberCount(role.UsersTable, role.UsersPrimaryKey[1])).
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(rows))
	for _, row := range rows {
		out[row.ID] = row.Members
	}
	return out, nil
}

// memberCount adds to "SELECT id FROM groups WHERE ..." a column "members":
// the number of (not deleted) users linked to the row through joinTable
// (user_groups or user_roles), counted by PostgreSQL:
//
//	(SELECT COUNT(*) FROM "user_groups" AS j JOIN "users" AS u ON u."id" = j."user_id"
//	 WHERE j."group_id" = "groups"."id" AND u."deleted_at" IS NULL) AS "members"
//
// Before, every member's id was loaded into Go to be counted there.
func memberCount(joinTable, ownerColumn string) ent.AggregateFunc {
	return func(s *sql.Selector) string {
		return fmt.Sprintf(`(SELECT COUNT(*) FROM %s AS j JOIN %s AS u ON u.%s = j.%s WHERE j.%s = %s AND u.%s IS NULL) AS %s`,
			quoteIdent(joinTable), quoteIdent(user.Table), quoteIdent(user.FieldID), quoteIdent("user_id"),
			quoteIdent(ownerColumn), s.C("id"), quoteIdent(user.FieldDeletedAt), quoteIdent("members"))
	}
}

// realFactor: an active factor that can answer a challenge on its own.
// Backup codes are a recovery tool, they do not count as "MFA enrolled".
func realFactor() predicate.MfaMethod {
	return mfamethod.And(
		mfamethod.StatusEQ(entschema.MfaMethodStatus(domain.MfaMethodActive)),
		mfamethod.TypeNEQ(entschema.MfaMethodType(domain.MfaMethodBackupCodes)),
	)
}

func (r *entAdminRepository) UsersWithActiveMFA(ctx context.Context, userIDs []string) (map[string]bool, error) {
	out := make(map[string]bool, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	ids, err := r.client.MfaMethod.Query().
		Where(mfamethod.UserIDIn(userIDs...), realFactor()).
		Unique(true).
		Select(mfamethod.FieldUserID).
		Strings(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

func (r *entAdminRepository) LastSuccessfulLogins(ctx context.Context, userIDs []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		UserID string    `json:"user_id"`
		Max    time.Time `json:"max"`
	}
	err := r.client.LoginAttempt.Query().
		Where(loginattempt.UserIDIn(userIDs...), loginattempt.StatusEQ(entschema.LoginAttemptSuccess)).
		GroupBy(loginattempt.FieldUserID).
		Aggregate(ent.Max(loginattempt.FieldCreatedAt)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.UserID] = row.Max
	}
	return out, nil
}

// --- roles, groups --------------------------------------------------------------

func (r *entAdminRepository) RoleGrants(ctx context.Context, roleID string) (repository.Grants, error) {
	e, err := r.client.Role.Query().
		Where(role.ID(roleID)).
		WithPermissions().
		WithClientScopes().
		Only(ctx)
	if err != nil {
		return repository.Grants{}, mapNotFound(err)
	}
	g := repository.Grants{PermissionIDs: []string{}, ClientScopeIDs: []string{}}
	for _, p := range e.Edges.Permissions {
		g.PermissionIDs = append(g.PermissionIDs, p.ID)
	}
	for _, cs := range e.Edges.ClientScopes {
		g.ClientScopeIDs = append(g.ClientScopeIDs, cs.ID)
	}
	return g, nil
}

func (r *entAdminRepository) GroupGrants(ctx context.Context, groupID string) (repository.Grants, error) {
	e, err := r.client.Group.Query().
		Where(group.ID(groupID)).
		WithPermissions().
		WithClientScopes().
		Only(ctx)
	if err != nil {
		return repository.Grants{}, mapNotFound(err)
	}
	g := repository.Grants{PermissionIDs: []string{}, ClientScopeIDs: []string{}}
	for _, p := range e.Edges.Permissions {
		g.PermissionIDs = append(g.PermissionIDs, p.ID)
	}
	for _, cs := range e.Edges.ClientScopes {
		g.ClientScopeIDs = append(g.ClientScopeIDs, cs.ID)
	}
	return g, nil
}

func (r *entAdminRepository) RealmRoleGrants(ctx context.Context, realmID string) (map[string]repository.Grants, error) {
	rows, err := r.client.Role.Query().
		Where(role.RealmID(realmID)).
		Select(role.FieldID).
		WithPermissions(func(q *ent.PermissionQuery) { q.Select(permission.FieldID) }).
		WithClientScopes(func(q *ent.ClientScopeQuery) { q.Select(clientscope.FieldID) }).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]repository.Grants, len(rows))
	for _, e := range rows {
		out[e.ID] = grantsOf(e.Edges.Permissions, e.Edges.ClientScopes)
	}
	return out, nil
}

func (r *entAdminRepository) RealmGroupGrants(ctx context.Context, realmID string) (map[string]repository.Grants, error) {
	rows, err := r.client.Group.Query().
		Where(group.RealmID(realmID)).
		Select(group.FieldID).
		WithPermissions(func(q *ent.PermissionQuery) { q.Select(permission.FieldID) }).
		WithClientScopes(func(q *ent.ClientScopeQuery) { q.Select(clientscope.FieldID) }).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]repository.Grants, len(rows))
	for _, e := range rows {
		out[e.ID] = grantsOf(e.Edges.Permissions, e.Edges.ClientScopes)
	}
	return out, nil
}

func grantsOf(perms []*ent.Permission, scopes []*ent.ClientScope) repository.Grants {
	g := repository.Grants{PermissionIDs: []string{}, ClientScopeIDs: []string{}}
	for _, p := range perms {
		g.PermissionIDs = append(g.PermissionIDs, p.ID)
	}
	for _, cs := range scopes {
		g.ClientScopeIDs = append(g.ClientScopeIDs, cs.ID)
	}
	return g
}

func (r *entAdminRepository) SetRolePermissions(ctx context.Context, roleID string, ids []string) error {
	return mapNotFound(r.client.Role.UpdateOneID(roleID).ClearPermissions().AddPermissionIDs(ids...).Exec(ctx))
}

func (r *entAdminRepository) SetGroupPermissions(ctx context.Context, groupID string, ids []string) error {
	return mapNotFound(r.client.Group.UpdateOneID(groupID).ClearPermissions().AddPermissionIDs(ids...).Exec(ctx))
}

func (r *entAdminRepository) SetRoleClientScopes(ctx context.Context, roleID string, ids []string) error {
	return mapNotFound(r.client.Role.UpdateOneID(roleID).ClearClientScopes().AddClientScopeIDs(ids...).Exec(ctx))
}

func (r *entAdminRepository) SetGroupClientScopes(ctx context.Context, groupID string, ids []string) error {
	return mapNotFound(r.client.Group.UpdateOneID(groupID).ClearClientScopes().AddClientScopeIDs(ids...).Exec(ctx))
}

func (r *entAdminRepository) SetManagedBy(ctx context.Context, kind, id, managedBy string) error {
	switch kind {
	case "role":
		return mapNotFound(r.client.Role.UpdateOneID(id).SetManagedBy(entschema.RoleManagedBy(managedBy)).Exec(ctx))
	case "group":
		return mapNotFound(r.client.Group.UpdateOneID(id).SetManagedBy(entschema.GroupManagedBy(managedBy)).Exec(ctx))
	default:
		return fmt.Errorf("entstore: SetManagedBy: unknown kind %q", kind)
	}
}

// --- clients --------------------------------------------------------------------

func (r *entAdminRepository) ClientGrants(ctx context.Context, clientRef string) (repository.ClientGrants, error) {
	out := repository.ClientGrants{RoleIDs: []string{}, GroupIDs: []string{}, Scopes: []repository.ScopeMapping{},
		Names: map[string]string{}}
	// Each link is loaded with the name of what it points to (Ent eager
	// loading: one more query per kind, not one per role, group or scope).
	roles, err := r.client.ClientRole.Query().Where(clientrole.ClientAppID(clientRef)).
		WithRole(func(q *ent.RoleQuery) { q.Select(role.FieldID, role.FieldName) }).All(ctx)
	if err != nil {
		return out, err
	}
	for _, x := range roles {
		out.RoleIDs = append(out.RoleIDs, x.RoleID)
		if x.Edges.Role != nil {
			out.Names[x.RoleID] = x.Edges.Role.Name
		}
	}
	groups, err := r.client.ClientGroup.Query().Where(clientgroup.ClientAppID(clientRef)).
		WithGroup(func(q *ent.GroupQuery) { q.Select(group.FieldID, group.FieldName) }).All(ctx)
	if err != nil {
		return out, err
	}
	for _, x := range groups {
		out.GroupIDs = append(out.GroupIDs, x.GroupID)
		if x.Edges.Group != nil {
			out.Names[x.GroupID] = x.Edges.Group.Name
		}
	}
	maps, err := r.client.ClientScopeMapping.Query().Where(clientscopemapping.ClientAppID(clientRef)).
		WithClientScope(func(q *ent.ClientScopeQuery) {
			q.Select(clientscope.FieldID, clientscope.FieldName, clientscope.FieldProtocol)
		}).All(ctx)
	if err != nil {
		return out, err
	}
	for _, x := range maps {
		m := repository.ScopeMapping{ClientScopeID: x.ClientScopeID, Required: x.Required}
		if cs := x.Edges.ClientScope; cs != nil {
			m.Name, m.Protocol = cs.Name, string(cs.Protocol)
		}
		out.Scopes = append(out.Scopes, m)
	}
	return out, nil
}

// SetClientRoles replaces the roles allowed to use a client, in one
// transaction (a client must never be briefly open or closed to everyone).
// Unchanged rows are kept, with their original granted_at / granted_by.
func (r *entAdminRepository) SetClientRoles(ctx context.Context, clientRef string, roleIDs []string, grantedBy string) error {
	return withTx(ctx, r.client, func(tx *ent.Tx) error {
		current, err := tx.ClientRole.Query().Where(clientrole.ClientAppID(clientRef)).All(ctx)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, x := range current {
			if !slices.Contains(roleIDs, x.RoleID) {
				if err := tx.ClientRole.DeleteOneID(x.ID).Exec(ctx); err != nil {
					return err
				}
				continue
			}
			have[x.RoleID] = true
		}
		for _, id := range uniq(roleIDs) {
			if have[id] {
				continue
			}
			if err := tx.ClientRole.Create().SetClientAppID(clientRef).SetRoleID(id).
				SetNillableGrantedBy(nonEmpty(grantedBy)).Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *entAdminRepository) SetClientGroups(ctx context.Context, clientRef string, groupIDs []string, grantedBy string) error {
	return withTx(ctx, r.client, func(tx *ent.Tx) error {
		current, err := tx.ClientGroup.Query().Where(clientgroup.ClientAppID(clientRef)).All(ctx)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, x := range current {
			if !slices.Contains(groupIDs, x.GroupID) {
				if err := tx.ClientGroup.DeleteOneID(x.ID).Exec(ctx); err != nil {
					return err
				}
				continue
			}
			have[x.GroupID] = true
		}
		for _, id := range uniq(groupIDs) {
			if have[id] {
				continue
			}
			if err := tx.ClientGroup.Create().SetClientAppID(clientRef).SetGroupID(id).
				SetNillableGrantedBy(nonEmpty(grantedBy)).Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *entAdminRepository) SetClientScopes(ctx context.Context, clientRef string, scopes []repository.ScopeMapping) error {
	want := map[string]bool{} // scope id -> required
	for _, s := range scopes {
		want[s.ClientScopeID] = want[s.ClientScopeID] || s.Required
	}
	return withTx(ctx, r.client, func(tx *ent.Tx) error {
		current, err := tx.ClientScopeMapping.Query().Where(clientscopemapping.ClientAppID(clientRef)).All(ctx)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, x := range current {
			req, keep := want[x.ClientScopeID]
			switch {
			case !keep:
				if err := tx.ClientScopeMapping.DeleteOneID(x.ID).Exec(ctx); err != nil {
					return err
				}
			case req != x.Required:
				if err := tx.ClientScopeMapping.UpdateOneID(x.ID).SetRequired(req).Exec(ctx); err != nil {
					return err
				}
			}
			have[x.ClientScopeID] = true
		}
		for id, req := range want {
			if have[id] {
				continue
			}
			if err := tx.ClientScopeMapping.Create().SetClientAppID(clientRef).SetClientScopeID(id).
				SetRequired(req).Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *entAdminRepository) ScopeUsage(ctx context.Context, realmID string) (map[string]int, error) {
	rows, err := r.client.ClientScopeMapping.Query().
		Where(clientscopemapping.HasClientAppWith(clientapp.RealmID(realmID), clientapp.DeletedAtIsNil())).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, m := range rows {
		out[m.ClientScopeID]++
	}
	return out, nil
}

func (r *entAdminRepository) CountActiveClients(ctx context.Context, realmID string) (int, error) {
	return r.client.ClientApp.Query().
		Where(clientapp.RealmID(realmID), clientapp.DeletedAtIsNil(),
			clientapp.StatusEQ(entschema.ClientAppStatus(domain.ClientAppActive))).
		Count(ctx)
}

// --- sessions -------------------------------------------------------------------

func liveToken(now time.Time) predicate.Token {
	return token.And(token.Revoked(false), token.ExpiresAtGT(now))
}

func sessionPredicates(f repository.SessionSearch) []predicate.Session {
	preds := []predicate.Session{
		session.RealmID(f.RealmID),
		session.Status(activeStatus),
		session.ExpiresAtGT(f.Now),
		session.LastActivityAtGT(f.IdleSince),
	}
	if f.UserID != "" {
		preds = append(preds, session.UserID(f.UserID))
	}
	if f.ClientRef != "" {
		preds = append(preds, session.HasTokensWith(token.ClientRefID(f.ClientRef), liveToken(f.Now)))
	}
	return preds
}

func (r *entAdminRepository) CountSessions(ctx context.Context, f repository.SessionSearch) (int, error) {
	return r.client.Session.Query().Where(sessionPredicates(f)...).Count(ctx)
}

func (r *entAdminRepository) SearchSessions(ctx context.Context, f repository.SessionSearch) ([]*domain.Session, int, error) {
	q := r.client.Session.Query().Where(sessionPredicates(f)...)
	offset, limit := clampPage(f.Page)
	rows, err := q.Clone().Order(ent.Desc(session.FieldLastActivityAt)).Offset(offset).Limit(limit).All(ctx)
	if err != nil {
		return nil, 0, err
	}
	total, err := pageTotal(ctx, f.Page, offset, limit, len(rows), q.Count)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*domain.Session, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainSession(e))
	}
	return out, total, nil
}

func (r *entAdminRepository) SessionClients(ctx context.Context, sessionIDs []string, now time.Time) (map[string][]string, error) {
	out := make(map[string][]string, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		SessionID   string `json:"session_id"`
		ClientRefID string `json:"client_ref_id"`
	}
	err := r.client.Token.Query().
		Where(token.SessionIDIn(sessionIDs...), liveToken(now)).
		Unique(true).
		Select(token.FieldSessionID, token.FieldClientRefID).
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !slices.Contains(out[row.SessionID], row.ClientRefID) {
			out[row.SessionID] = append(out[row.SessionID], row.ClientRefID)
		}
	}
	return out, nil
}

// --- audit log, sign-ins --------------------------------------------------------

func (r *entAdminRepository) SearchAuditLogs(ctx context.Context, f repository.AuditSearch) ([]*domain.AuditLog, int, error) {
	preds := []predicate.AuditLog{auditlog.RealmID(f.RealmID)}
	if f.UserID != "" {
		preds = append(preds, auditlog.Or(
			auditlog.UserID(f.UserID),
			auditlog.And(auditlog.ResourceType("User"), auditlog.ResourceID(f.UserID)),
		))
	}
	if f.ClientRef != "" {
		preds = append(preds, auditlog.ResourceType("ClientApp"), auditlog.ResourceID(f.ClientRef))
	}
	if f.Action != "" {
		preds = append(preds, auditlog.Action(f.Action))
	}
	if f.Status != "" {
		preds = append(preds, auditlog.StatusEQ(entschema.AuditLogStatus(f.Status)))
	}
	if len(f.Levels) > 0 {
		levels := make([]entschema.AuditLogLevel, 0, len(f.Levels))
		for _, l := range f.Levels {
			levels = append(levels, entschema.AuditLogLevel(l))
		}
		preds = append(preds, auditlog.LevelIn(levels...))
	}
	if !f.From.IsZero() {
		preds = append(preds, auditlog.TimestampGTE(f.From))
	}
	if !f.To.IsZero() {
		preds = append(preds, auditlog.TimestampLT(f.To))
	}
	q := r.client.AuditLog.Query().Where(preds...)
	offset, limit := clampPage(f.Page)
	rows, err := q.Clone().Order(ent.Desc(auditlog.FieldTimestamp), ent.Desc(auditlog.FieldID)).Offset(offset).Limit(limit).All(ctx)
	if err != nil {
		return nil, 0, err
	}
	total, err := pageTotal(ctx, f.Page, offset, limit, len(rows), q.Count)
	if err != nil {
		return nil, 0, err
	}
	return toDomainAuditLogs(rows), total, nil
}

// LoginCounts: successes and failures since a time, in one query
// (SELECT status, COUNT(*) ... GROUP BY status).
func (r *entAdminRepository) LoginCounts(ctx context.Context, realmID string, since time.Time) (int, int, error) {
	var rows []struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	err := r.client.LoginAttempt.Query().
		Where(loginattempt.RealmID(realmID), loginattempt.CreatedAtGTE(since),
			loginattempt.StatusIn(entschema.LoginAttemptSuccess, entschema.LoginAttemptFailure)).
		GroupBy(loginattempt.FieldStatus).
		Aggregate(ent.Count()).
		Scan(ctx, &rows)
	if err != nil {
		return 0, 0, err
	}
	var ok, ko int
	for _, row := range rows {
		switch entschema.LoginAttemptStatus(row.Status) {
		case entschema.LoginAttemptSuccess:
			ok = row.Count
		case entschema.LoginAttemptFailure:
			ko = row.Count
		}
	}
	return ok, ko, nil
}

func (r *entAdminRepository) LoginAttemptsByUser(ctx context.Context, userID string, limit int) ([]*domain.LoginAttempt, error) {
	if limit <= 0 || limit > maxPageSize {
		limit = maxPageSize
	}
	rows, err := r.client.LoginAttempt.Query().
		Where(loginattempt.UserID(userID)).
		Order(ent.Desc(loginattempt.FieldCreatedAt)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainLoginAttempts(rows), nil
}

// --- MFA, timeouts ----------------------------------------------------------------

// MFACoverage: active users, and how many of them have a real factor, in
// one query:
//
//	SELECT COUNT(*) AS "count",
//	       COALESCE(SUM(CASE WHEN EXISTS (SELECT 1 FROM "mfa_methods" AS m
//	           WHERE m."user_id" = "users"."id" AND m."status" = 'active'
//	           AND m."type" <> 'backup_codes') THEN 1 ELSE 0 END), 0) AS "enrolled"
//	FROM "users" WHERE realm_id = $1 AND deleted_at IS NULL AND status = 'active'
func (r *entAdminRepository) MFACoverage(ctx context.Context, realmID string) (int, int, error) {
	var rows []struct {
		Count    int `json:"count"`
		Enrolled int `json:"enrolled"`
	}
	err := r.client.User.Query().
		Where(user.RealmID(realmID), user.DeletedAtIsNil(), user.StatusEQ(entschema.UserActive)).
		Aggregate(ent.Count(), func(s *sql.Selector) string {
			return fmt.Sprintf(`COALESCE(SUM(CASE WHEN EXISTS (SELECT 1 FROM %s AS m WHERE m.%s = %s AND m.%s = %s AND m.%s <> %s) THEN 1 ELSE 0 END), 0) AS %s`,
				quoteIdent(mfamethod.Table), quoteIdent(mfamethod.FieldUserID), s.C(user.FieldID),
				quoteIdent(mfamethod.FieldStatus), quoteLiteral(string(domain.MfaMethodActive)),
				quoteIdent(mfamethod.FieldType), quoteLiteral(string(domain.MfaMethodBackupCodes)),
				quoteIdent("enrolled"))
		}).
		Scan(ctx, &rows)
	if err != nil || len(rows) == 0 {
		return 0, 0, err
	}
	return rows[0].Enrolled, rows[0].Count, nil
}

func (r *entAdminRepository) ListTimeouts(ctx context.Context, realmID string) ([]*domain.Timeout, error) {
	rows, err := r.client.Timeout.Query().
		Where(timeout.RealmID(realmID)).
		Order(ent.Desc(timeout.FieldStartsAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Timeout, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainTimeout(e))
	}
	return out, nil
}

// --- helpers --------------------------------------------------------------------

// withTx runs fn in a transaction, rolled back on error or panic.
func withTx(ctx context.Context, client *ent.Client, fn func(tx *ent.Tx) error) (err error) {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func uniq(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
