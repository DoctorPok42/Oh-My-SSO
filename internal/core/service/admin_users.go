package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


const InviteActivationTTL = 7 * 24 * time.Hour

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$`)

func checkUsername(u string) error {
	if !usernamePattern.MatchString(u) {
		return adminInvalid("username", "username: 1-128 characters among letters, digits and . _ @ + - (starting with a letter or digit)")
	}
	return nil
}

func checkEmail(e string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(e))
	if err != nil || addr.Name != "" || len(addr.Address) > 320 {
		return "", adminInvalid("email", "a plain e-mail address is required")
	}
	return addr.Address, nil
}

// UserSummary is a row of the user list.
type UserSummary struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	Name        string            `json:"name"`
	Status      domain.UserStatus `json:"status"`
	HasPassword bool              `json:"has_password"` // false: invitation not accepted yet
	MFAEnrolled bool              `json:"mfa_enrolled"`
	Locked      bool              `json:"locked"`
	LastLoginAt *time.Time        `json:"last_login_at"`
	CreatedAt   time.Time         `json:"created_at"`
	Groups      []NameRef         `json:"groups"`
	Roles       []NameRef         `json:"roles"`
}

// UserDetail is the user drawer: summary, profile, factors, rights.
type UserDetail struct {
	UserSummary
	Profile         map[string]interface{} `json:"profile"`
	FailedLogins    int                    `json:"failed_logins"`
	LockedUntil     *time.Time             `json:"locked_until"`
	Factors         []FactorView           `json:"factors"`
	BackupCodesLeft int                    `json:"backup_codes_left"`
	Effective       EffectiveAccess        `json:"effective"`
}

// FactorView: a second factor, as an admin may see it (never its secret).
type FactorView struct {
	ID         string               `json:"id"`
	Type       domain.MfaMethodType `json:"type"`
	Name       string               `json:"name"`
	CreatedAt  time.Time            `json:"created_at"`
	LastUsedAt *time.Time           `json:"last_used_at"`
}

// EffectiveAccess: union of what the user's active groups and roles grant.
type EffectiveAccess struct {
	Permissions  []EffectiveGrant `json:"permissions"`
	ClientScopes []EffectiveGrant `json:"client_scopes"`
}

// EffectiveGrant: one permission or scope, and where it comes from
// ("group:engineering", "role:support").
type EffectiveGrant struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
}

func displayName(u *domain.User) string {
	if n, ok := u.Profile["name"].(string); ok && strings.TrimSpace(n) != "" {
		return n
	}
	given, _ := u.Profile["given_name"].(string)
	family, _ := u.Profile["family_name"].(string)
	if n := strings.TrimSpace(given + " " + family); n != "" {
		return n
	}
	return u.Username
}

// ListUsers returns one page of the realm's users.
func (s *AdminService) ListUsers(ctx context.Context, realm *domain.Realm, f repository.UserSearch) ([]UserSummary, int, error) {
	f.RealmID = realm.ID
	users, total, err := s.d.Admin.SearchUsers(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	out, err := s.summaries(ctx, users)
	return out, total, err
}

func (s *AdminService) summaries(ctx context.Context, users []*domain.User) ([]UserSummary, error) {
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	members, err := s.d.Admin.Memberships(ctx, ids)
	if err != nil {
		return nil, err
	}
	mfa, err := s.d.Admin.UsersWithActiveMFA(ctx, ids)
	if err != nil {
		return nil, err
	}
	last, err := s.d.Admin.LastSuccessfulLogins(ctx, ids)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	out := make([]UserSummary, 0, len(users))
	for _, u := range users {
		sum := UserSummary{
			ID: u.ID, Username: u.Username, Email: u.Email, Name: displayName(u), Status: u.Status,
			HasPassword: u.PasswordHash != "", MFAEnrolled: mfa[u.ID], Locked: u.Lockout.LockedAt(now),
			CreatedAt: u.CreatedAt,
			// Names loaded with the memberships: no query per group or role.
			Groups: namedRefs(members[u.ID].GroupIDs, members[u.ID].Names),
			Roles:  namedRefs(members[u.ID].RoleIDs, members[u.ID].Names),
		}
		if t, ok := last[u.ID]; ok {
			sum.LastLoginAt = &t
		}
		out = append(out, sum)
	}
	return out, nil
}

// GetUser returns the user drawer.
func (s *AdminService) GetUser(ctx context.Context, realm *domain.Realm, userID string) (*UserDetail, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	sums, err := s.summaries(ctx, []*domain.User{u})
	if err != nil {
		return nil, err
	}
	d := &UserDetail{UserSummary: sums[0], Profile: u.Profile, FailedLogins: u.Lockout.FailedCount,
		Factors: []FactorView{}}
	if d.Profile == nil {
		d.Profile = map[string]interface{}{}
	}
	if u.Lockout.LockedAt(s.d.Now()) {
		t := u.Lockout.LockedUntil
		d.LockedUntil = &t
	}
	factors, err := s.d.MFA.ListFactors(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, m := range factors.Methods {
		fv := FactorView{ID: m.ID, Type: m.Type, Name: m.Name, CreatedAt: m.CreatedAt}
		if !m.LastUsedAt.IsZero() {
			t := m.LastUsedAt
			fv.LastUsedAt = &t
		}
		d.Factors = append(d.Factors, fv)
	}
	d.BackupCodesLeft = factors.BackupCodes.Remaining
	if d.Effective, err = s.effectiveAccess(ctx, u.ID); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *AdminService) effectiveAccess(ctx context.Context, userID string) (EffectiveAccess, error) {
	out := EffectiveAccess{Permissions: []EffectiveGrant{}, ClientScopes: []EffectiveGrant{}}
	access, err := s.d.Access.GetUserAccess(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	perms := map[string]*EffectiveGrant{}
	scopes := map[string]*EffectiveGrant{}
	add := func(set map[string]*EffectiveGrant, id, name, source string) {
		g, ok := set[id]
		if !ok {
			g = &EffectiveGrant{ID: id, Name: name}
			set[id] = g
		}
		if !slices.Contains(g.Sources, source) {
			g.Sources = append(g.Sources, source)
		}
	}
	for _, src := range slices.Concat(access.Groups, access.Roles) {
		if !src.Active || src.RealmID != access.RealmID {
			continue
		}
		label := string(src.Kind) + ":" + src.Name
		for _, p := range src.Permissions {
			if p.Status == domain.PermissionActive || p.Status == "" {
				add(perms, p.ID, p.Name, label)
			}
		}
		for _, cs := range src.ClientScopes {
			add(scopes, cs.ID, cs.Name, label)
		}
	}
	for _, g := range perms {
		out.Permissions = append(out.Permissions, *g)
	}
	for _, g := range scopes {
		out.ClientScopes = append(out.ClientScopes, *g)
	}
	byName := func(a, b EffectiveGrant) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(out.Permissions, byName)
	slices.SortFunc(out.ClientScopes, byName)
	return out, nil
}

// InviteUserInput: the "+ Invite user" drawer.
type InviteUserInput struct {
	Username string
	Email    string
	Profile  map[string]interface{} // e.g. given_name, family_name
	GroupIDs []string
	RoleIDs  []string
	// SendEmail: e-mail the activation link (when e-mail is configured).
	// Otherwise the link is returned once, for the admin to pass on.
	SendEmail bool
}

// InviteResult: the new account and, when it was not e-mailed, its link.
type InviteResult struct {
	User          *UserDetail `json:"user"`
	Emailed       bool        `json:"emailed"`
	ActivationURL string      `json:"activation_url,omitempty"`
	ExpiresAt     time.Time   `json:"expires_at"`
}

// InviteUser creates an account without password and its activation link.
func (s *AdminService) InviteUser(ctx context.Context, actor AdminActor, realm *domain.Realm, in InviteUserInput) (*InviteResult, error) {
	username := strings.TrimSpace(in.Username)
	email, err := checkEmail(in.Email)
	if err != nil {
		return nil, err
	}
	if username == "" {
		username, _, _ = strings.Cut(email, "@")
	}
	if err := checkUsername(username); err != nil {
		return nil, err
	}
	profile, err := cleanProfile(nil, in.Profile)
	if err != nil {
		return nil, err
	}
	groups, err := s.checkGroupIDs(ctx, realm.ID, in.GroupIDs)
	if err != nil {
		return nil, err
	}
	roles, err := s.checkRoleIDs(ctx, realm.ID, in.RoleIDs)
	if err != nil {
		return nil, err
	}
	if err := s.checkUnique(ctx, realm.ID, "", username, email); err != nil {
		return nil, err
	}

	u, err := s.d.Users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: username, Email: email, Status: domain.UserActive,
	})
	if err != nil {
		return nil, fmt.Errorf("invite user: %w", err)
	}
	if len(profile) > 0 {
		if err := s.d.Admin.SetUserProfile(ctx, u.ID, profile); err != nil {
			return nil, err
		}
	}
	if err := s.d.Admin.SetUserGroups(ctx, u.ID, groups); err != nil {
		return nil, err
	}
	if err := s.d.Admin.SetUserRoles(ctx, u.ID, roles); err != nil {
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.invite", "User", u.ID, domain.AuditLogInfo, map[string]interface{}{
		"username": username, "email": email, "group_ids": groups, "role_ids": roles,
	})
	res, err := s.issueActivation(ctx, actor, realm, u, in.SendEmail)
	if err != nil {
		return nil, err
	}
	if res.User, err = s.GetUser(ctx, realm, u.ID); err != nil {
		return nil, err
	}
	return res, nil
}

// ResendActivation issues a new activation link for an account that has
// not chosen its password yet (the previous link stops working). For an
// activated account it is refused: users who forgot their password use
// "forgot password", an admin never sets or resets it for them.
func (s *AdminService) ResendActivation(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string, sendEmail bool) (*InviteResult, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	if u.PasswordHash != "" {
		return nil, adminRefused("already_activated", "this account already chose its password: activation links are only for new accounts")
	}
	res, err := s.issueActivation(ctx, actor, realm, u, sendEmail)
	if err != nil {
		return nil, err
	}
	if res.User, err = s.GetUser(ctx, realm, u.ID); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *AdminService) issueActivation(ctx context.Context, actor AdminActor, realm *domain.Realm, u *domain.User, sendEmail bool) (*InviteResult, error) {
	token, expires, err := s.d.PasswordReset.IssueActivationToken(ctx, u, InviteActivationTTL, actor.By())
	if err != nil {
		return nil, err
	}
	res := &InviteResult{ExpiresAt: expires}
	if sendEmail && s.d.EmailEnabled {
		s.d.Notifier.Notify(ctx, domain.NotificationEvent{
			Kind: domain.NotificationAccountInvite, RealmID: realm.ID, UserID: u.ID,
			OccurredAt: s.d.Now(), ResetToken: token, ExpiresAt: expires,
			IPAddress: actor.IPAddress, UserAgent: actor.UserAgent,
		})
		res.Emailed = true
	} else {
		res.ActivationURL = s.activationURL(realm.Name, token)
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.activation_link", "User", u.ID, domain.AuditLogInfo, map[string]interface{}{
		"emailed": res.Emailed, "expires_at": expires.UTC().Format(time.RFC3339),
	})
	return res, nil
}

// UpdateUserInput: nil fields are unchanged. Profile keys are merged; a nil
// value removes the key.
type UpdateUserInput struct {
	Username *string
	Email    *string
	Status   *domain.UserStatus
	Profile  map[string]interface{}
}

// UpdateUser changes a user. A user who is no longer active is signed out
// everywhere at once.
func (s *AdminService) UpdateUser(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string, in UpdateUserInput) (*UserDetail, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	params := repository.UpdateUserParams{}
	changes := map[string]interface{}{}
	if in.Username != nil && *in.Username != u.Username {
		name := strings.TrimSpace(*in.Username)
		if err := checkUsername(name); err != nil {
			return nil, err
		}
		params.Username = &name
		changes["username"] = name
	}
	if in.Email != nil && *in.Email != u.Email {
		email, err := checkEmail(*in.Email)
		if err != nil {
			return nil, err
		}
		params.Email = &email
		changes["email"] = email
	}
	if params.Username != nil || params.Email != nil {
		name, email := "", ""
		if params.Username != nil {
			name = *params.Username
		}
		if params.Email != nil {
			email = *params.Email
		}
		if err := s.checkUnique(ctx, realm.ID, u.ID, name, email); err != nil {
			return nil, err
		}
	}
	deactivate := false
	if in.Status != nil && *in.Status != u.Status {
		switch *in.Status {
		case domain.UserActive, domain.UserInactive, domain.UserSuspended:
		default:
			return nil, adminInvalid("status", "status must be active, inactive or suspended")
		}
		if *in.Status != domain.UserActive {
			if err := s.guardAdminRemoval(ctx, actor, realm, u.ID, "suspend or deactivate"); err != nil {
				return nil, err
			}
			deactivate = true
		}
		params.Status = in.Status
		changes["status"] = string(*in.Status)
	}
	if params.Username != nil || params.Email != nil || params.Status != nil {
		if _, err := s.d.Users.Update(ctx, u.ID, params); err != nil {
			return nil, fmt.Errorf("update user: %w", err)
		}
	}
	if in.Profile != nil {
		profile, err := cleanProfile(u.Profile, in.Profile)
		if err != nil {
			return nil, err
		}
		if err := s.d.Admin.SetUserProfile(ctx, u.ID, profile); err != nil {
			return nil, err
		}
		changes["profile_keys"] = slices.Sorted(maps.Keys(in.Profile))
	}
	if deactivate {
		if err := s.d.Sessions.RevokeAllForUser(ctx, u.ID, domain.SessionRevokedAdminRevoked); err != nil {
			return nil, fmt.Errorf("update user: sign out: %w", err)
		}
	}
	if len(changes) > 0 {
		level := domain.AuditLogInfo
		if deactivate {
			level = domain.AuditLogWarning
		}
		s.auditAdmin(ctx, actor, realm.ID, "user.update", "User", u.ID, level, changes)
	}
	return s.GetUser(ctx, realm, u.ID)
}

// DeleteUser removes an account for good (sessions, factors, consents go
// with it). The audit log keeps its history.
func (s *AdminService) DeleteUser(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string) error {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return err
	}
	if err := s.guardAdminRemoval(ctx, actor, realm, u.ID, "delete"); err != nil {
		return err
	}
	if err := s.d.Sessions.RevokeAllForUser(ctx, u.ID, domain.SessionRevokedAdminRevoked); err != nil {
		return fmt.Errorf("delete user: sign out: %w", err)
	}
	if err := s.d.Users.Delete(ctx, u.ID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.delete", "User", u.ID, domain.AuditLogWarning, map[string]interface{}{
		"username": u.Username, "email": u.Email,
	})
	return nil
}

// SetUserGroups replaces the user's groups.
func (s *AdminService) SetUserGroups(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string, groupIDs []string) (*UserDetail, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	ids, err := s.checkGroupIDs(ctx, realm.ID, groupIDs)
	if err != nil {
		return nil, err
	}
	if isMaster(realm) {
		admins, err := s.d.Groups.GetByRealmAndName(ctx, realm.ID, AdminGroupName)
		if err == nil && !slices.Contains(ids, admins.ID) {
			m, err := s.d.Admin.Memberships(ctx, []string{u.ID})
			if err != nil {
				return nil, err
			}
			if slices.Contains(m[u.ID].GroupIDs, admins.ID) {
				if err := s.guardAdminRemoval(ctx, actor, realm, u.ID, "remove from "+AdminGroupName); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := s.d.Admin.SetUserGroups(ctx, u.ID, ids); err != nil {
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.groups", "User", u.ID, domain.AuditLogInfo, map[string]interface{}{"group_ids": ids})
	return s.GetUser(ctx, realm, u.ID)
}

// SetUserRoles replaces the user's direct roles. Prefer groups (spec:
// a role assigned directly is harder to audit at scale).
func (s *AdminService) SetUserRoles(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string, roleIDs []string) (*UserDetail, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	ids, err := s.checkRoleIDs(ctx, realm.ID, roleIDs)
	if err != nil {
		return nil, err
	}
	if err := s.d.Admin.SetUserRoles(ctx, u.ID, ids); err != nil {
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.roles", "User", u.ID, domain.AuditLogInfo, map[string]interface{}{"role_ids": ids})
	return s.GetUser(ctx, realm, u.ID)
}

// ResetUserMFA removes every factor of a user and signs them out (the
// "Reset MFA (revoke all)" button). Not for yourself: use the account console.
func (s *AdminService) ResetUserMFA(ctx context.Context, actor AdminActor, realm *domain.Realm, userID, reason string) (*ResetResult, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	if isMaster(realm) && u.ID == actor.UserID {
		return nil, adminRefused("self_change", "you cannot reset your own factors here: use your account console")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, adminInvalid("reason", "a reason is required (it goes to the audit log)")
	}
	res, err := s.d.MFA.ResetUser(ctx, u, actor.By(), reason)
	if err != nil {
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.mfa_reset", "User", u.ID, domain.AuditLogWarning, map[string]interface{}{
		"reason": reason, "methods_deleted": res.MethodsDeleted,
	})
	return res, nil
}

// UnlockUser clears the failed sign-ins and the lock of an account.
func (s *AdminService) UnlockUser(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string) error {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return err
	}
	if err := s.d.Lockout.Unlock(ctx, u); err != nil {
		return err
	}
	s.auditAdmin(ctx, actor, realm.ID, "user.unlock", "User", u.ID, domain.AuditLogWarning, nil)
	return nil
}

// --- guardrails -----------------------------------------------------------------

func isMaster(realm *domain.Realm) bool {
	return realm.IsSystemRealm && realm.Name == MasterRealmName
}

// guardAdminRemoval refuses, in the master realm, to lock yourself out or
// to leave the instance without any active administrator.
func (s *AdminService) guardAdminRemoval(ctx context.Context, actor AdminActor, realm *domain.Realm, userID, what string) error {
	if !isMaster(realm) {
		return nil
	}
	if userID == actor.UserID {
		return adminRefused("self_change", "you cannot %s your own account", what)
	}
	admins, err := s.d.Groups.GetByRealmAndName(ctx, realm.ID, AdminGroupName)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	members, err := s.d.Admin.ActiveGroupMemberIDs(ctx, admins.ID)
	if err != nil {
		return err
	}
	if len(members) == 1 && members[0] == userID {
		return adminRefused("last_admin", "this is the last active administrator: add another one to %q first", AdminGroupName)
	}
	return nil
}

// checkUnique: username and e-mail are unique in a realm (database index);
// a clear error is better than a constraint violation.
func (s *AdminService) checkUnique(ctx context.Context, realmID, selfID, username, email string) error {
	if username != "" {
		if u, err := s.d.Users.GetByRealmAndUsername(ctx, realmID, username); err == nil && u.ID != selfID {
			return adminConflict("username_taken", "username %q is already used in this realm", username)
		} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return err
		}
	}
	if email != "" {
		if u, err := s.d.Users.GetByRealmAndEmail(ctx, realmID, email); err == nil && u.ID != selfID {
			return adminConflict("email_taken", "e-mail %q is already used in this realm", email)
		} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return err
		}
	}
	return nil
}

// cleanProfile merges patch into current. Only flat values (text, number,
// boolean) are accepted; a nil value removes the key. Keys are short
// identifiers (they become "profile.<key>" for claim mappers).
var profileKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func cleanProfile(current, patch map[string]interface{}) (map[string]interface{}, error) {
	out := maps.Clone(current)
	if out == nil {
		out = map[string]interface{}{}
	}
	for k, v := range patch {
		if !profileKeyPattern.MatchString(k) {
			return nil, adminInvalid("profile", "profile key %q: lowercase letters, digits and _ only", k)
		}
		switch val := v.(type) {
		case nil:
			delete(out, k)
		case string:
			if len(val) > 1024 {
				return nil, adminInvalid("profile", "profile value of %q is too long", k)
			}
			out[k] = strings.TrimSpace(val)
		case bool, float64, int, int64:
			out[k] = val
		default:
			return nil, adminInvalid("profile", "profile value of %q must be text, a number or a boolean", k)
		}
	}
	if len(out) > 64 {
		return nil, adminInvalid("profile", "at most 64 profile keys")
	}
	return out, nil
}
