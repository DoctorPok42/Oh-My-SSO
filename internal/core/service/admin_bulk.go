package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// The most items one bulk action may touch: the realm's bulk_limit
// (Settings), DefaultBulkLimit until it is changed. A selection larger than
// that is done in several passes, so a mistake stays small. MaxBulkLimit
// keeps one action within the console's wait (BULK_TIMEOUT_MS): the items
// are done one after the other.
const (
	DefaultBulkLimit = 100
	MaxBulkLimit     = 500
)

// BulkLimit is the realm's bulk_limit, DefaultBulkLimit when it has no
// settings yet (or a value out of range).
func (s *AdminService) BulkLimit(ctx context.Context, realmID string) (int, error) {
	st, err := s.settingsOf(ctx, realmID)
	if err != nil {
		return 0, err
	}
	return effectiveBulkLimit(st), nil
}

func effectiveBulkLimit(st *domain.InstanceSettings) int {
	if st.BulkLimit < 1 || st.BulkLimit > MaxBulkLimit {
		return DefaultBulkLimit
	}
	return st.BulkLimit
}

// What became of one item of a bulk action.
const (
	BulkDone    = "done"
	BulkSkipped = "skipped" // a guardrail or nothing to do: the sentence says why
	BulkFailed  = "failed"  // a server problem: logged, never shown
)

// The actions of POST /users/bulk.
const (
	BulkSuspend            = "suspend"
	BulkReactivate         = "reactivate"
	BulkUnlock             = "unlock"
	BulkForcePasswordReset = "force_password_reset"
	BulkResetMFA           = "reset_mfa"
	BulkAddGroup           = "add_group"
	BulkRemoveGroup        = "remove_group"
	BulkAddRole            = "add_role"
	BulkRemoveRole         = "remove_role"
	BulkResendInvite       = "resend_invite"
	BulkDelete             = "delete"
)

// The actions of POST /sessions/bulk.
const (
	BulkRevoke      = "revoke"       // ids of sessions
	BulkRevokeUsers = "revoke_users" // ids of users: all their sessions
)

// BulkInput is one bulk request.
type BulkInput struct {
	Action  string
	IDs     []string
	Reason  string // reset_mfa
	GroupID string // add_group, remove_group
	RoleID  string // add_role, remove_role
}

// BulkItem is the outcome of one item.
type BulkItem struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// BulkResult is the summary of a bulk action. The audit entries of the items
// carry OperationID.
type BulkResult struct {
	OperationID string     `json:"operation_id"`
	Action      string     `json:"action"`
	Done        int        `json:"done"`
	Skipped     int        `json:"skipped"`
	Failed      int        `json:"failed"`
	Items       []BulkItem `json:"items"`
}

type bulkOperationKey struct{}

// bulkOperation is the id of the running bulk action ("" outside one):
// auditAdminAbout writes it in every entry.
func bulkOperation(ctx context.Context) string {
	id, _ := ctx.Value(bulkOperationKey{}).(string)
	return id
}

func newBulkOperationID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("bulk: operation id: %w", err)
	}
	return "op_" + hex.EncodeToString(b), nil
}

// cleanBulkIDs drops empty and repeated ids, in order, and applies the
// realm's bulk limit.
func (s *AdminService) cleanBulkIDs(ctx context.Context, realm *domain.Realm, ids []string) ([]string, error) {
	limit, err := s.BulkLimit(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, adminInvalid("ids", i18n.M("admin.error.bulk_empty", "select at least one item"))
	}
	if len(out) > limit {
		return nil, adminText(AdminInvalid, "bulk_limit", "ids", i18n.M("admin.error.bulk_limit", "at most {limit} items at a time", "limit", limit))
	}
	return out, nil
}

func bulkUnknownAction() error {
	return adminInvalid("action", i18n.M("admin.error.bulk_action", "unknown bulk action"))
}

// bulkStep works on one item: it returns the name to show for it, even when
// it fails, and an error when the item was not changed.
type bulkStep func(ctx context.Context, id string) (label string, err error)

// runBulk does the items one after the other: the guardrails read the
// current state, so a selection holding every administrator stops at the
// last one. The console hanging up does not stop it half-way.
func (s *AdminService) runBulk(ctx context.Context, action string, ids []string, loc *i18n.Localizer, step bulkStep) (*BulkResult, error) {
	op, err := newBulkOperationID()
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(context.WithoutCancel(ctx), bulkOperationKey{}, op)
	res := &BulkResult{OperationID: op, Action: action, Items: make([]BulkItem, 0, len(ids))}
	for _, id := range ids {
		label, err := step(ctx, id)
		if label == "" {
			label = id
		}
		item := BulkItem{ID: id, Label: label, Status: BulkDone}
		var ae *AdminError
		switch {
		case err == nil:
			res.Done++
		case errors.As(err, &ae):
			item.Status, item.Code, item.Message = BulkSkipped, ae.Code, s.bulkErrorText(ctx, err, loc)
			res.Skipped++
		default:
			item.Status, item.Code, item.Message = BulkFailed, "internal_error", s.bulkErrorText(ctx, err, loc)
			res.Failed++
		}
		res.Items = append(res.Items, item)
	}
	return res, nil
}

func (s *AdminService) bulkErrorText(ctx context.Context, err error, loc *i18n.Localizer) string {
	var ae *AdminError
	if errors.As(err, &ae) {
		if ae.Text.Key != "" {
			return loc.Text(ae.Text)
		}
		return ae.Message
	}
	s.d.Logger.ErrorContext(ctx, "bulk action: item failed", "operation_id", bulkOperation(ctx), "error", err)
	return loc.Text(i18n.M("admin.error.internal", "something went wrong on the server, see its logs"))
}

// userStep is an action on one user, already loaded.
type userStep func(ctx context.Context, u *domain.User) error

// BulkUsers runs one action on many users.
func (s *AdminService) BulkUsers(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	step, err := s.userBulkStep(ctx, actor, realm, in)
	if err != nil {
		return nil, err
	}
	return s.runBulk(ctx, in.Action, ids, loc, s.onUsers(actor, realm, step))
}

// onUsers loads each user and leaves out the administrator who asked: in
// the master realm, a bulk action could lock them out of the console.
func (s *AdminService) onUsers(actor AdminActor, realm *domain.Realm, step userStep) bulkStep {
	return func(ctx context.Context, id string) (string, error) {
		u, err := s.userInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		if isMaster(realm) && u.ID == actor.UserID {
			return u.Username, adminRefused("self_change", i18n.M("admin.error.bulk_self", "your own account is left out of bulk actions"))
		}
		return u.Username, step(ctx, u)
	}
}

// userBulkStep checks what the whole request needs (a request that cannot
// work is refused, not skipped item by item) and chooses the action.
func (s *AdminService) userBulkStep(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput) (userStep, error) {
	switch in.Action {
	case BulkSuspend:
		return func(ctx context.Context, u *domain.User) error {
			if u.Status == domain.UserSuspended {
				return bulkSkip("already_suspended", i18n.M("admin.error.bulk_already_suspended", "already suspended"))
			}
			return s.setUserStatus(ctx, actor, realm, u, domain.UserSuspended)
		}, nil
	case BulkReactivate:
		return func(ctx context.Context, u *domain.User) error {
			if u.Status == domain.UserActive {
				return bulkSkip("already_active", i18n.M("admin.error.bulk_already_active", "already active"))
			}
			return s.setUserStatus(ctx, actor, realm, u, domain.UserActive)
		}, nil
	case BulkUnlock:
		return func(ctx context.Context, u *domain.User) error {
			if !u.Lockout.LockedAt(s.d.Now()) {
				return bulkSkip("not_locked", i18n.M("admin.error.bulk_not_locked", "not locked"))
			}
			return s.UnlockUser(ctx, actor, realm, u.ID)
		}, nil
	case BulkForcePasswordReset:
		return func(ctx context.Context, u *domain.User) error {
			return s.forcePasswordReset(ctx, actor, realm, u)
		}, nil
	case BulkResetMFA:
		reason := strings.TrimSpace(in.Reason)
		if reason == "" {
			return nil, adminInvalid("reason", i18n.M("admin.error.reason_required", "a reason is required (it goes to the audit log)"))
		}
		return func(ctx context.Context, u *domain.User) error {
			enrolled, err := s.d.Admin.UsersWithActiveMFA(ctx, []string{u.ID})
			if err != nil {
				return err
			}
			if !enrolled[u.ID] {
				return bulkSkip("no_mfa", i18n.M("admin.error.bulk_no_mfa", "no second factor enrolled"))
			}
			_, err = s.ResetUserMFA(ctx, actor, realm, u.ID, reason)
			return err
		}, nil
	case BulkAddGroup, BulkRemoveGroup:
		ids, err := s.checkGroupIDs(ctx, realm.ID, []string{in.GroupID})
		if err != nil {
			return nil, err
		}
		add := in.Action == BulkAddGroup
		return func(ctx context.Context, u *domain.User) error {
			m, err := s.d.Admin.Memberships(ctx, []string{u.ID})
			if err != nil {
				return err
			}
			next, err := toggleMembership(m[u.ID].GroupIDs, ids[0], add,
				bulkSkip("already_member", i18n.M("admin.error.bulk_already_member", "already in this group")),
				bulkSkip("not_member", i18n.M("admin.error.bulk_not_member", "not in this group")))
			if err != nil {
				return err
			}
			_, err = s.SetUserGroups(ctx, actor, realm, u.ID, next)
			return err
		}, nil
	case BulkAddRole, BulkRemoveRole:
		ids, err := s.checkRoleIDs(ctx, realm.ID, []string{in.RoleID})
		if err != nil {
			return nil, err
		}
		add := in.Action == BulkAddRole
		return func(ctx context.Context, u *domain.User) error {
			m, err := s.d.Admin.Memberships(ctx, []string{u.ID})
			if err != nil {
				return err
			}
			next, err := toggleMembership(m[u.ID].RoleIDs, ids[0], add,
				bulkSkip("already_assigned", i18n.M("admin.error.bulk_already_assigned", "already has this role")),
				bulkSkip("not_assigned", i18n.M("admin.error.bulk_not_assigned", "does not hold this role directly")))
			if err != nil {
				return err
			}
			_, err = s.SetUserRoles(ctx, actor, realm, u.ID, next)
			return err
		}, nil
	case BulkResendInvite:
		return func(ctx context.Context, u *domain.User) error {
			if !s.d.EmailEnabled {
				return bulkEmailDisabled()
			}
			res, err := s.ResendActivation(ctx, actor, realm, u.ID, true)
			if err != nil {
				return err
			}
			if !res.Emailed {
				// The link exists but nobody got it: a bulk answer never carries links.
				return bulkSkip("email_not_sent", i18n.M("admin.error.bulk_email_not_sent", "the e-mail could not be queued, try again"))
			}
			return nil
		}, nil
	case BulkDelete:
		return func(ctx context.Context, u *domain.User) error {
			return s.DeleteUser(ctx, actor, realm, u.ID)
		}, nil
	}
	return nil, bulkUnknownAction()
}

func bulkSkip(code string, t i18n.Text) error { return adminRefused(code, t) }

func bulkEmailDisabled() error {
	return bulkSkip("email_disabled", i18n.M("admin.error.bulk_email_disabled", "e-mail is not configured on this server"))
}

// toggleMembership is the new list of a user's groups or roles, or the given
// error when the action changes nothing.
func toggleMembership(current []string, id string, add bool, already, absent error) ([]string, error) {
	has := slices.Contains(current, id)
	switch {
	case add && has:
		return nil, already
	case !add && !has:
		return nil, absent
	case add:
		return append(slices.Clone(current), id), nil
	}
	return slices.DeleteFunc(slices.Clone(current), func(x string) bool { return x == id }), nil
}

func (s *AdminService) setUserStatus(ctx context.Context, actor AdminActor, realm *domain.Realm, u *domain.User, status domain.UserStatus) error {
	_, err := s.UpdateUser(ctx, actor, realm, u.ID, UpdateUserInput{Status: &status})
	return err
}

// forcePasswordReset: the user is signed out everywhere and gets a link by
// e-mail; signing in with the password is refused until it changes. Without
// e-mail nobody could get out of that state, so the user is skipped.
func (s *AdminService) forcePasswordReset(ctx context.Context, actor AdminActor, realm *domain.Realm, u *domain.User) error {
	switch {
	case !s.d.EmailEnabled:
		return bulkEmailDisabled()
	case u.Status != domain.UserActive:
		return bulkSkip("not_active", i18n.M("admin.error.bulk_not_active", "this account is not active"))
	case u.PasswordHash == "":
		return bulkSkip("no_password", i18n.M("admin.error.bulk_no_password", "this account has no password"))
	case u.MustChangePassword:
		return bulkSkip("already_required", i18n.M("admin.error.bulk_reset_already_required", "a new password is already required"))
	}
	if err := s.guardAdminRemoval(ctx, actor, realm, u.ID, i18n.M("admin.error.bulk_self", "your own account is left out of bulk actions")); err != nil {
		return err
	}
	// The link first: if it cannot be created, nothing changed for the user.
	if err := s.d.PasswordReset.SendForcedResetLink(ctx, u, actor.IPAddress); err != nil {
		return err
	}
	required := true
	if _, err := s.d.Users.Update(ctx, u.ID, repository.UpdateUserParams{MustChangePassword: &required}); err != nil {
		return fmt.Errorf("force password reset: %w", err)
	}
	if err := s.d.Sessions.RevokeAllForUser(ctx, u.ID, domain.SessionRevokedAdminRevoked); err != nil {
		return fmt.Errorf("force password reset: sign out: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.UserPasswordResetForced, "User", u.ID, domain.AuditLogWarning, nil)
	return nil
}

// BulkSessions revokes sessions, chosen one by one or by user.
func (s *AdminService) BulkSessions(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkResult, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	switch in.Action {
	case BulkRevoke:
		return s.runBulk(ctx, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
			return s.bulkRevokeSession(ctx, actor, realm, id)
		})
	case BulkRevokeUsers:
		return s.runBulk(ctx, in.Action, ids, loc, s.onUsers(actor, realm, func(ctx context.Context, u *domain.User) error {
			win, err := s.activeWindow(ctx, realm)
			if err != nil {
				return err
			}
			win.UserID = u.ID
			live, err := s.d.Admin.CountSessions(ctx, win)
			if err != nil {
				return err
			}
			if live == 0 {
				return bulkSkip("no_session", i18n.M("admin.error.bulk_no_session", "no active session"))
			}
			return s.RevokeUserSessions(ctx, actor, realm, u.ID)
		}))
	}
	return nil, bulkUnknownAction()
}

func (s *AdminService) bulkRevokeSession(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) (string, error) {
	label := ""
	if se, err := s.d.Sessions.GetActive(ctx, id); err == nil && se.RealmID == realm.ID {
		if u, err := s.d.Users.GetByID(ctx, se.UserID); err == nil {
			label = u.Username
		}
	}
	if id == actor.SessionID {
		return label, bulkSkip("own_session", i18n.M("admin.error.bulk_own_session", "your own session is left out of bulk actions"))
	}
	return label, s.RevokeSession(ctx, actor, realm, id)
}
