package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// Bulk actions on what is not a user or a session. Each one goes through the
// unitary method, so the guardrails and the audit entry stay in one place.

// The other bulk actions (delete, suspend, reactivate: see admin_bulk.go).
const (
	BulkDuplicate = "duplicate" // roles
	BulkLift      = "lift"      // timeouts
)

// BulkClients suspends, reactivates or deletes clients. Those managed by the
// configuration are skipped by the unitary methods.
func (s *AdminService) BulkClients(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	var step func(ctx context.Context, app *domain.ClientApp) error
	switch in.Action {
	case BulkSuspend, BulkReactivate:
		active := in.Action == BulkReactivate
		step = func(ctx context.Context, app *domain.ClientApp) error {
			if (app.Status == domain.ClientAppActive) == active {
				if active {
					return bulkSkip("already_active", i18n.M("admin.error.bulk_already_active", "already active"))
				}
				return bulkSkip("already_suspended", i18n.M("admin.error.bulk_already_suspended", "already suspended"))
			}
			_, err := s.UpdateClient(ctx, actor, realm, app.ID, ClientInput{Active: &active})
			return err
		}
	case BulkDelete:
		step = func(ctx context.Context, app *domain.ClientApp) error {
			return s.DeleteClient(ctx, actor, realm, app.ID)
		}
	default:
		return nil, bulkUnknownAction()
	}
	return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
		app, err := s.clientInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		return app.Name, step(ctx, app)
	})
}

// ExportClients gives the configuration of the clients. A ClientView never
// holds a secret.
func (s *AdminService) ExportClients(ctx context.Context, realm *domain.Realm, ids []string) ([]ClientView, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, ids)
	if err != nil {
		return nil, err
	}
	out := make([]ClientView, 0, len(ids))
	for _, id := range ids {
		v, err := s.GetClient(ctx, realm, id)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// BulkGroups deletes groups.
func (s *AdminService) BulkGroups(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	if in.Action != BulkDelete {
		return nil, bulkUnknownAction()
	}
	return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
		g, err := s.groupInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		return g.Name, s.DeleteGroup(ctx, actor, realm, g.ID)
	})
}

// AddGroupMembers adds users, given by username or e-mail, to a group.
func (s *AdminService) AddGroupMembers(ctx context.Context, actor AdminActor, realm *domain.Realm, groupID string, identifiers []string, loc *i18n.Localizer) (*BulkResult, error) {
	names, err := s.cleanBulkIDs(ctx, realm, identifiers)
	if err != nil {
		return nil, err
	}
	g, err := s.groupInRealm(ctx, realm.ID, groupID)
	if err != nil {
		return nil, err
	}
	return s.runBulk(ctx, "add_members", names, loc, func(ctx context.Context, name string) (string, error) {
		u, err := findUserByIdentifier(ctx, s.d.Users, realm.ID, name)
		if errors.Is(err, repository.ErrNotFound) {
			return name, adminNotFound(i18n.M("admin.error.not_found.user", "user not found"))
		}
		if err != nil {
			return name, err
		}
		m, err := s.d.Admin.Memberships(ctx, []string{u.ID})
		if err != nil {
			return name, err
		}
		if slices.Contains(m[u.ID].GroupIDs, g.ID) {
			return name, bulkSkip("already_member", i18n.M("admin.error.bulk_already_member", "already in this group"))
		}
		return name, s.onUsers(actor, realm, func(ctx context.Context, u *domain.User) error {
			_, err := s.SetUserGroups(ctx, actor, realm, u.ID, append(slices.Clone(m[u.ID].GroupIDs), g.ID))
			return err
		}).run(ctx, u.ID)
	})
}

// run is the step without its label, for a caller that has its own.
func (b bulkStep) run(ctx context.Context, id string) error {
	_, err := b(ctx, id)
	return err
}

// BulkRoles deletes or duplicates roles. The unitary delete allows a role
// still assigned (the assignments go with it): one by one, an administrator
// sees the member count; on a whole selection, that would strip rights from
// people nobody looked at, so such a role is skipped.
func (s *AdminService) BulkRoles(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	var step func(ctx context.Context, r *domain.Role) error
	switch in.Action {
	case BulkDelete:
		step = func(ctx context.Context, r *domain.Role) error {
			counts, err := s.d.Admin.RoleMemberCounts(ctx, realm.ID)
			if err != nil {
				return err
			}
			if n := counts[r.ID]; n > 0 {
				return adminConflict("in_use", i18n.M("admin.error.bulk_role_assigned", "still assigned to {count} user(s)", "count", n))
			}
			return s.DeleteRole(ctx, actor, realm, r.ID)
		}
	case BulkDuplicate:
		step = func(ctx context.Context, r *domain.Role) error {
			return s.duplicateRole(ctx, actor, realm, r)
		}
	default:
		return nil, bulkUnknownAction()
	}
	return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
		r, err := s.roleInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		return r.Name, step(ctx, r)
	})
}

// duplicateRole creates "<name>-copy" (then -copy-2...) with the same
// permissions and client scopes, without its members. A copy of a role
// managed by the configuration is an ordinary role.
func (s *AdminService) duplicateRole(ctx context.Context, actor AdminActor, realm *domain.Realm, r *domain.Role) error {
	grants, err := s.d.Admin.RoleGrants(ctx, r.ID)
	if err != nil {
		return err
	}
	name, err := s.freeRoleName(ctx, realm.ID, r.Name)
	if err != nil {
		return err
	}
	perms, scopes := nonNil(grants.PermissionIDs), nonNil(grants.ClientScopeIDs)
	_, err = s.CreateRole(ctx, actor, realm, AccessInput{Name: &name, Description: &r.Description, PermissionIDs: &perms, ClientScopeIDs: &scopes})
	return err
}

// maxRoleName: see accessNamePattern.
const maxRoleName = 64

// maxRoleCopies: "-copy", "-copy-2"... are tried up to "-copy-100".
const maxRoleCopies = 100

func (s *AdminService) freeRoleName(ctx context.Context, realmID, name string) (string, error) {
	for i := 1; i <= maxRoleCopies; i++ {
		suffix := "-copy"
		if i > 1 {
			suffix = fmt.Sprintf("-copy-%d", i)
		}
		base := name
		if len(base)+len(suffix) > maxRoleName {
			base = strings.TrimRight(base[:maxRoleName-len(suffix)], " ")
		}
		candidate := base + suffix
		_, err := s.d.Roles.GetByRealmAndName(ctx, realmID, candidate)
		if errors.Is(err, repository.ErrNotFound) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", adminConflict("name_taken", i18n.M("admin.error.role_name_taken", "a role named \"{name}\" already exists", "name", name+"-copy"))
}

// BulkClientScopes deletes client scopes. One still mapped to a client is
// skipped by the unitary method.
func (s *AdminService) BulkClientScopes(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	if in.Action != BulkDelete {
		return nil, bulkUnknownAction()
	}
	return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
		cs, err := s.scopeInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		return cs.Name, s.DeleteClientScope(ctx, actor, realm, cs.ID)
	})
}

// BulkTimeouts lifts timeouts. There is no delete: a timeout stays in the
// history once it is over.
func (s *AdminService) BulkTimeouts(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	if in.Action != BulkLift {
		return nil, bulkUnknownAction()
	}
	return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
		v, err := s.LiftTimeout(ctx, actor, realm, id)
		if err != nil {
			return "", err
		}
		return v.Target.Name, nil
	})
}
