package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Roles, groups and permissions in the Admin API (Step 14).
//
// A group or a role is the ONLY place where rights are granted: its
// permissions (internal to the IdP) and its client scopes (what goes into
// tokens). Groups are preferred: the role screen shows
// domain.RoleSecurityNotice (spec: "less auditable than a group at scale").

var accessNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$`)

// AccessView is a role or a group with what it grants.
type AccessView struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"` // "role" or "group"
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Status         string    `json:"status"`
	ManagedBy      string    `json:"managed_by"`
	Members        int       `json:"members"`
	PermissionIDs  []string  `json:"permission_ids"`
	ClientScopeIDs []string  `json:"client_scope_ids"`
	CreatedAt      time.Time `json:"created_at"`
	// Notice: the "prefer groups" warning, on roles only.
	Notice string `json:"notice,omitempty"`
}

// AccessInput creates or changes a role or a group. nil: unchanged (on
// update); on create, nil means empty.
type AccessInput struct {
	Name           *string
	Description    *string
	Active         *bool
	PermissionIDs  *[]string
	ClientScopeIDs *[]string
}

func (s *AdminService) ListRoles(ctx context.Context, realm *domain.Realm) ([]AccessView, error) {
	roles, err := s.d.Roles.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	_, counts, err := s.d.Admin.MemberCounts(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]AccessView, 0, len(roles))
	for _, r := range roles {
		v, err := s.roleView(ctx, r, counts[r.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *AdminService) ListGroups(ctx context.Context, realm *domain.Realm) ([]AccessView, error) {
	groups, err := s.d.Groups.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	counts, _, err := s.d.Admin.MemberCounts(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]AccessView, 0, len(groups))
	for _, g := range groups {
		v, err := s.groupView(ctx, g, counts[g.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *AdminService) roleView(ctx context.Context, r *domain.Role, members int) (AccessView, error) {
	grants, err := s.d.Admin.RoleGrants(ctx, r.ID)
	if err != nil {
		return AccessView{}, err
	}
	return AccessView{ID: r.ID, Kind: "role", Name: r.Name, Description: r.Description, Status: string(r.Status),
		ManagedBy: string(r.ManagedBy), Members: members, PermissionIDs: grants.PermissionIDs,
		ClientScopeIDs: grants.ClientScopeIDs, CreatedAt: r.CreatedAt, Notice: domain.RoleSecurityNotice}, nil
}

func (s *AdminService) groupView(ctx context.Context, g *domain.Group, members int) (AccessView, error) {
	grants, err := s.d.Admin.GroupGrants(ctx, g.ID)
	if err != nil {
		return AccessView{}, err
	}
	return AccessView{ID: g.ID, Kind: "group", Name: g.Name, Description: g.Description, Status: string(g.Status),
		ManagedBy: string(g.ManagedBy), Members: members, PermissionIDs: grants.PermissionIDs,
		ClientScopeIDs: grants.ClientScopeIDs, CreatedAt: g.CreatedAt}, nil
}

func (s *AdminService) checkAccessInput(ctx context.Context, realm *domain.Realm, in AccessInput) (perms, scopes []string, err error) {
	if in.Name != nil && !accessNamePattern.MatchString(strings.TrimSpace(*in.Name)) {
		return nil, nil, adminInvalid("name", "name: 1-64 characters among letters, digits, space and . _ : -")
	}
	if in.Description != nil && len(*in.Description) > 512 {
		return nil, nil, adminInvalid("description", "description: at most 512 characters")
	}
	if in.PermissionIDs != nil {
		if perms, err = s.checkPermissionIDs(ctx, realm.ID, *in.PermissionIDs); err != nil {
			return nil, nil, err
		}
	}
	if in.ClientScopeIDs != nil {
		if scopes, err = s.checkScopeIDs(ctx, realm.ID, *in.ClientScopeIDs); err != nil {
			return nil, nil, err
		}
	}
	return perms, scopes, nil
}

func strOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return strings.TrimSpace(*p)
}

func (s *AdminService) CreateRole(ctx context.Context, actor AdminActor, realm *domain.Realm, in AccessInput) (AccessView, error) {
	if in.Name == nil {
		return AccessView{}, adminInvalid("name", "name is required")
	}
	perms, scopes, err := s.checkAccessInput(ctx, realm, in)
	if err != nil {
		return AccessView{}, err
	}
	name := strOr(in.Name, "")
	if _, err := s.d.Roles.GetByRealmAndName(ctx, realm.ID, name); err == nil {
		return AccessView{}, adminConflict("name_taken", "a role named %q already exists", name)
	}
	r, err := s.d.Roles.Create(ctx, repository.CreateRoleParams{RealmID: realm.ID, Name: name, Description: strOr(in.Description, "")})
	if err != nil {
		return AccessView{}, fmt.Errorf("create role: %w", err)
	}
	if err := s.d.Admin.SetRolePermissions(ctx, r.ID, perms); err != nil {
		return AccessView{}, err
	}
	if err := s.d.Admin.SetRoleClientScopes(ctx, r.ID, scopes); err != nil {
		return AccessView{}, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "role.create", "Role", r.ID, domain.AuditLogInfo, map[string]interface{}{
		"name": name, "permission_ids": perms, "client_scope_ids": scopes,
	})
	return s.roleView(ctx, r, 0)
}

func (s *AdminService) UpdateRole(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, in AccessInput) (AccessView, error) {
	r, err := s.roleInRealm(ctx, realm.ID, id)
	if err != nil {
		return AccessView{}, err
	}
	if r.ManagedBy == domain.RoleManagedByConfig {
		return AccessView{}, errManagedByConfig
	}
	perms, scopes, err := s.checkAccessInput(ctx, realm, in)
	if err != nil {
		return AccessView{}, err
	}
	params := repository.UpdateRoleParams{}
	details := map[string]interface{}{}
	if in.Name != nil && strOr(in.Name, "") != r.Name {
		name := strOr(in.Name, "")
		if _, err := s.d.Roles.GetByRealmAndName(ctx, realm.ID, name); err == nil {
			return AccessView{}, adminConflict("name_taken", "a role named %q already exists", name)
		}
		params.Name = &name
		details["name"] = name
	}
	if in.Description != nil {
		d := strOr(in.Description, "")
		params.Description = &d
		details["description"] = d
	}
	if in.Active != nil {
		st := domain.RoleInactive
		if *in.Active {
			st = domain.RoleActive
		}
		params.Status = &st
		details["status"] = string(st)
	}
	if params.Name != nil || params.Description != nil || params.Status != nil {
		if r, err = s.d.Roles.Update(ctx, r.ID, params); err != nil {
			return AccessView{}, fmt.Errorf("update role: %w", err)
		}
	}
	if in.PermissionIDs != nil {
		if err := s.d.Admin.SetRolePermissions(ctx, r.ID, perms); err != nil {
			return AccessView{}, err
		}
		details["permission_ids"] = perms
	}
	if in.ClientScopeIDs != nil {
		if err := s.d.Admin.SetRoleClientScopes(ctx, r.ID, scopes); err != nil {
			return AccessView{}, err
		}
		details["client_scope_ids"] = scopes
	}
	if len(details) > 0 {
		s.auditAdmin(ctx, actor, realm.ID, "role.update", "Role", r.ID, domain.AuditLogInfo, details)
	}
	_, counts, err := s.d.Admin.MemberCounts(ctx, realm.ID)
	if err != nil {
		return AccessView{}, err
	}
	return s.roleView(ctx, r, counts[r.ID])
}

func (s *AdminService) DeleteRole(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) error {
	r, err := s.roleInRealm(ctx, realm.ID, id)
	if err != nil {
		return err
	}
	if r.ManagedBy == domain.RoleManagedByConfig {
		return errManagedByConfig
	}
	if err := s.d.Roles.Delete(ctx, r.ID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "role.delete", "Role", r.ID, domain.AuditLogWarning, map[string]interface{}{"name": r.Name})
	return nil
}

func (s *AdminService) CreateGroup(ctx context.Context, actor AdminActor, realm *domain.Realm, in AccessInput) (AccessView, error) {
	if in.Name == nil {
		return AccessView{}, adminInvalid("name", "name is required")
	}
	perms, scopes, err := s.checkAccessInput(ctx, realm, in)
	if err != nil {
		return AccessView{}, err
	}
	name := strOr(in.Name, "")
	if _, err := s.d.Groups.GetByRealmAndName(ctx, realm.ID, name); err == nil {
		return AccessView{}, adminConflict("name_taken", "a group named %q already exists", name)
	}
	g, err := s.d.Groups.Create(ctx, repository.CreateGroupParams{RealmID: realm.ID, Name: name, Description: strOr(in.Description, "")})
	if err != nil {
		return AccessView{}, fmt.Errorf("create group: %w", err)
	}
	if err := s.d.Admin.SetGroupPermissions(ctx, g.ID, perms); err != nil {
		return AccessView{}, err
	}
	if err := s.d.Admin.SetGroupClientScopes(ctx, g.ID, scopes); err != nil {
		return AccessView{}, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "group.create", "Group", g.ID, domain.AuditLogInfo, map[string]interface{}{
		"name": name, "permission_ids": perms, "client_scope_ids": scopes,
	})
	return s.groupView(ctx, g, 0)
}

func (s *AdminService) UpdateGroup(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, in AccessInput) (AccessView, error) {
	g, err := s.groupInRealm(ctx, realm.ID, id)
	if err != nil {
		return AccessView{}, err
	}
	if g.ManagedBy == domain.GroupManagedByConfig {
		return AccessView{}, errManagedByConfig
	}
	perms, scopes, err := s.checkAccessInput(ctx, realm, in)
	if err != nil {
		return AccessView{}, err
	}
	params := repository.UpdateGroupParams{}
	details := map[string]interface{}{}
	if in.Name != nil && strOr(in.Name, "") != g.Name {
		name := strOr(in.Name, "")
		if _, err := s.d.Groups.GetByRealmAndName(ctx, realm.ID, name); err == nil {
			return AccessView{}, adminConflict("name_taken", "a group named %q already exists", name)
		}
		params.Name = &name
		details["name"] = name
	}
	if in.Description != nil {
		d := strOr(in.Description, "")
		params.Description = &d
		details["description"] = d
	}
	if in.Active != nil {
		st := domain.GroupInactive
		if *in.Active {
			st = domain.GroupActive
		}
		params.Status = &st
		details["status"] = string(st)
	}
	if params.Name != nil || params.Description != nil || params.Status != nil {
		if g, err = s.d.Groups.Update(ctx, g.ID, params); err != nil {
			return AccessView{}, fmt.Errorf("update group: %w", err)
		}
	}
	if in.PermissionIDs != nil {
		if err := s.d.Admin.SetGroupPermissions(ctx, g.ID, perms); err != nil {
			return AccessView{}, err
		}
		details["permission_ids"] = perms
	}
	if in.ClientScopeIDs != nil {
		if err := s.d.Admin.SetGroupClientScopes(ctx, g.ID, scopes); err != nil {
			return AccessView{}, err
		}
		details["client_scope_ids"] = scopes
	}
	if len(details) > 0 {
		s.auditAdmin(ctx, actor, realm.ID, "group.update", "Group", g.ID, domain.AuditLogInfo, details)
	}
	counts, _, err := s.d.Admin.MemberCounts(ctx, realm.ID)
	if err != nil {
		return AccessView{}, err
	}
	return s.groupView(ctx, g, counts[g.ID])
}

func (s *AdminService) DeleteGroup(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) error {
	g, err := s.groupInRealm(ctx, realm.ID, id)
	if err != nil {
		return err
	}
	if g.ManagedBy == domain.GroupManagedByConfig {
		return errManagedByConfig
	}
	if err := s.d.Groups.Delete(ctx, g.ID); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "group.delete", "Group", g.ID, domain.AuditLogWarning, map[string]interface{}{"name": g.Name})
	return nil
}

// GroupMembers lists the users of a group (one page).
func (s *AdminService) GroupMembers(ctx context.Context, realm *domain.Realm, groupID string, page repository.Page) ([]UserSummary, int, error) {
	if _, err := s.groupInRealm(ctx, realm.ID, groupID); err != nil {
		return nil, 0, err
	}
	return s.ListUsers(ctx, realm, repository.UserSearch{GroupID: groupID, Page: page})
}

// --- permissions ----------------------------------------------------------------

// PermissionView: one permission of the realm's catalogue.
type PermissionView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	// System: part of the admin catalogue of the master realm (read-only).
	System bool `json:"system"`
}

var permissionPartPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

func (s *AdminService) ListPermissions(ctx context.Context, realm *domain.Realm) ([]PermissionView, error) {
	perms, err := s.d.Permissions.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]PermissionView, 0, len(perms))
	for _, p := range perms {
		out = append(out, PermissionView{ID: p.ID, Name: p.Name, Description: p.Description, Resource: p.Resource,
			Action: p.Action, System: isMaster(realm) && p.Scope == AdminPermissionScope})
	}
	slices.SortFunc(out, func(a, b PermissionView) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// CreatePermissionInput: "resource" and "action" name what the permission
// allows ("invoice", "approve"); its name is "resource:action".
type CreatePermissionInput struct {
	Resource    string
	Action      string
	Description string
}

func (s *AdminService) CreatePermission(ctx context.Context, actor AdminActor, realm *domain.Realm, in CreatePermissionInput) (PermissionView, error) {
	res, act := strings.TrimSpace(in.Resource), strings.TrimSpace(in.Action)
	if !permissionPartPattern.MatchString(res) || !permissionPartPattern.MatchString(act) {
		return PermissionView{}, adminInvalid("resource", "resource and action: lowercase letters, digits and _ . - (e.g. invoice / approve)")
	}
	if isMaster(realm) {
		return PermissionView{}, adminRefused("system_realm", "the permissions of the master realm are the admin catalogue: they cannot be added to")
	}
	name := res + ":" + act
	if _, err := s.d.Permissions.GetByRealmAndName(ctx, realm.ID, name); err == nil {
		return PermissionView{}, adminConflict("name_taken", "permission %q already exists", name)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return PermissionView{}, err
	}
	p, err := s.d.Permissions.Create(ctx, repository.CreatePermissionParams{RealmID: realm.ID, Name: name,
		Description: strings.TrimSpace(in.Description), Resource: res, Action: act, Scope: "realm"})
	if err != nil {
		return PermissionView{}, fmt.Errorf("create permission: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "permission.create", "Permission", p.ID, domain.AuditLogInfo, map[string]interface{}{"name": name})
	return PermissionView{ID: p.ID, Name: p.Name, Description: p.Description, Resource: p.Resource, Action: p.Action}, nil
}

func (s *AdminService) DeletePermission(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) error {
	p, err := s.d.Permissions.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && p.RealmID != realm.ID) {
		return adminNotFound("permission")
	}
	if err != nil {
		return err
	}
	if isMaster(realm) && p.Scope == AdminPermissionScope {
		return errManagedByConfig
	}
	if err := s.d.Permissions.Delete(ctx, p.ID); err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "permission.delete", "Permission", p.ID, domain.AuditLogWarning, map[string]interface{}{"name": p.Name})
	return nil
}
