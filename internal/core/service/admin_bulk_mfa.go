package service

import (
	"context"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/i18n"
)

// The actions of POST /mfa-policies/roles/bulk: the MFA policy of many roles.
const (
	BulkMFARequire   = "require"     // MFA required for the members
	BulkMFAOptional  = "optional"    // no longer required by the role
	BulkMFAStepUpOn  = "step_up_on"  // second factor again for sensitive actions
	BulkMFAStepUpOff = "step_up_off" // no step-up asked by the role
	BulkMFAInherit   = "inherit"     // back to the realm default
)

// BulkRoleMFA changes one setting of the MFA policy of many roles, through
// setRoleMFA / deleteRoleMFA (their audit entries carry the operation id).
// A role that follows the realm default gets its own rules with the defaults
// of the role form (any method, no grace period) and the setting asked; a
// role with its own rules keeps the others. Roles managed by the
// configuration are skipped.
func (s *AdminService) BulkRoleMFA(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	switch in.Action {
	case BulkMFARequire, BulkMFAOptional, BulkMFAStepUpOn, BulkMFAStepUpOff, BulkMFAInherit:
	default:
		return nil, bulkUnknownAction()
	}
	// One read for the whole selection: an item only changes its own role.
	view, err := s.MFAPolicies(ctx, realm)
	if err != nil {
		return nil, err
	}
	lines := make(map[string]RolePolicyView, len(view.Roles))
	for _, l := range view.Roles {
		lines[l.Role.ID] = l
	}
	return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
		r, err := s.roleInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		line := lines[r.ID] // zero value: a role created since, on the realm default
		if line.ManagedBy == string(domain.MfaPolicyManagedByConfig) {
			return r.Name, errManagedByConfig
		}
		if in.Action == BulkMFAInherit {
			if !line.Configured {
				return r.Name, bulkSkip("already_default", i18n.M("admin.error.bulk_mfa_already_default", "already follows the realm default"))
			}
			return r.Name, s.deleteRoleMFA(ctx, actor, realm, r)
		}
		next := RolePolicyInput{Required: line.Required, AllowedMethods: line.AllowedMethods,
			EnrollmentGraceDays: line.EnrollmentGraceDays, StepUpForSensitiveActions: line.StepUpForSensitiveActions}
		var unchanged error
		switch in.Action {
		case BulkMFARequire:
			next.Required = true
			unchanged = bulkSkip("already_required", i18n.M("admin.error.bulk_mfa_already_required", "MFA is already required"))
		case BulkMFAOptional:
			next.Required = false
			unchanged = bulkSkip("already_optional", i18n.M("admin.error.bulk_mfa_already_optional", "MFA is already not required by this role"))
		case BulkMFAStepUpOn:
			next.StepUpForSensitiveActions = true
			unchanged = bulkSkip("step_up_already_on", i18n.M("admin.error.bulk_mfa_step_up_already_on", "step-up is already on"))
		case BulkMFAStepUpOff:
			next.StepUpForSensitiveActions = false
			unchanged = bulkSkip("step_up_already_off", i18n.M("admin.error.bulk_mfa_step_up_already_off", "step-up is already off"))
		}
		// Off is what the realm default gives a role: no own rules for that.
		if next.Required == line.Required && next.StepUpForSensitiveActions == line.StepUpForSensitiveActions {
			return r.Name, unchanged
		}
		return r.Name, s.setRoleMFA(ctx, actor, realm, r, next)
	})
}
