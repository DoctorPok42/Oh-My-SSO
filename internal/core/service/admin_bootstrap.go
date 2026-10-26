package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


type AdminPermission struct {
	Resource    string
	Action      string
	Description string
}

// Name is "resource:action", e.g. "client:write".
func (p AdminPermission) Name() string { return p.Resource + ":" + p.Action }

// AdminPermissionScope marks the catalogue's permissions (Permission.scope).
const AdminPermissionScope = "admin"

// AdminPermissions lists every permission the Admin API checks. A "read"
// permission shows; "write" (or "rotate", "revoke") changes.
var AdminPermissions = []AdminPermission{
	{"realm", "read", "See realms"},
	{"realm", "write", "Create, rename, enable and disable realms"},
	{"client", "read", "See clients (OIDC and SAML applications)"},
	{"client", "write", "Create, change and delete clients, regenerate secrets"},
	{"client_scope", "read", "See client scopes"},
	{"client_scope", "write", "Create, change and delete client scopes"},
	{"session", "read", "See active sessions"},
	{"session", "revoke", "Sign users out"},
	{"audit_log", "read", "Read the audit log"},
	{"user", "read", "See users, their access and their factors"},
	{"user", "write", "Invite, change, suspend and delete users, reset their MFA"},
	{"access", "read", "See roles, groups and permissions"},
	{"access", "write", "Change roles, groups and permissions"},
	{"signing_key", "read", "See signing keys"},
	{"signing_key", "rotate", "Rotate signing keys"},
	{"mfa_policy", "read", "See MFA policies"},
	{"mfa_policy", "write", "Change MFA policies"},
	{"settings", "read", "See realm settings"},
	{"settings", "write", "Change realm settings"},
	{"timeout", "read", "See timeouts"},
}

// Groups created by the bootstrap, both managed by the system (read-only in
// the admin console: nobody can strip "admins" of its permissions by
// mistake). Membership is the only thing that changes.
const (
	AdminGroupName   = "admins"   // every permission
	AuditorGroupName = "auditors" // every "read" permission
)

// AdminConsoleCallbackPath is where the admin console receives the OIDC
// authorization code (admin/app/auth/callback in the Next.js app).
const AdminConsoleCallbackPath = "/auth/callback"

// AdminConsoleAccessTokenTTL is deliberately longer than the default used by
// regular OIDC clients because the admin console refreshes its own session
// independently.
const AdminConsoleAccessTokenTTL = 60 * time.Minute

// AdminConsoleStepUpMaxAge is the period during which sensitive console
// changes remain unlocked after MFA verification.
const AdminConsoleStepUpMaxAge = 60 * time.Minute

// Lifetime of the activation links of bootstrap and recovery accounts.
const BootstrapActivationTTL = 30 * time.Minute

var (
	// ErrAlreadyBootstrapped: an account of the master realm has already
	// chosen its password. Use `idp-admin recover`.
	ErrAlreadyBootstrapped = errors.New("the master realm is already set up: bootstrap runs only once (use `idp-admin recover` if every administrator lost access)")
	// ErrNotBootstrapped: recovery needs a set-up master realm.
	ErrNotBootstrapped = errors.New("the master realm is not set up yet: run `idp-admin bootstrap` first")
)

// BootstrapInput: what `idp-admin bootstrap` asks for.
type BootstrapInput struct {
	AdminEmail    string
	AdminUsername string // empty: the part of the e-mail before "@"
	// AdminConsoleURL is the URL of the Next.js admin console, e.g.
	// https://admin.example.com (http://localhost:3000 in development).
	AdminConsoleURL string
	// Actor: who runs the command, "cli:<os user>@<host>".
	Actor string
	// Production refuses an http:// console URL.
	Production bool
}

// BootstrapResult says what was created, and the two secrets shown once.
type BootstrapResult struct {
	Steps []string // human-readable, one per line

	AdminUsername     string
	ActivationURL     string
	ActivationExpires time.Time

	ClientID string
	// ClientSecret is only set when the client was created by this run.
	ClientSecret string
	// SigningKeyWarning: the master realm has no signing key yet (local_dev
	// KeyManager); admins cannot sign in until it has one.
	SigningKeyWarning string
}

// Bootstrap sets up the master realm. See the guardrails above.
func (s *AdminService) Bootstrap(ctx context.Context, in BootstrapInput) (*BootstrapResult, error) {
	email, username, err := checkBootstrapAccount(in.AdminEmail, in.AdminUsername)
	if err != nil {
		return nil, err
	}
	consoleURL, err := checkConsoleURL(in.AdminConsoleURL, in.Production)
	if err != nil {
		return nil, err
	}
	res := &BootstrapResult{ClientID: domain.InternalAdminClientID, AdminUsername: username}
	step := func(format string, a ...any) { res.Steps = append(res.Steps, fmt.Sprintf(format, a...)) }

	// 1. The realm, and the "runs once" rule, checked BEFORE any write.
	realm, err := s.d.Realms.GetByName(ctx, MasterRealmName)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		realm = nil
	case err != nil:
		return nil, fmt.Errorf("bootstrap: load master realm: %w", err)
	case !realm.IsSystemRealm:
		return nil, errors.New("bootstrap: a realm named \"master\" exists but is not the system realm: refusing to touch it")
	default:
		activated, err := s.d.Admin.CountUsersWithPassword(ctx, realm.ID)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
		if activated > 0 {
			return nil, ErrAlreadyBootstrapped
		}
	}
	if realm == nil {
		if realm, err = s.d.Admin.CreateSystemRealm(ctx, repository.CreateRealmParams{
			Name: MasterRealmName, DisplayName: "Administration",
		}); err != nil {
			return nil, fmt.Errorf("bootstrap: create master realm: %w", err)
		}
		step("realm %q: created (system realm)", MasterRealmName)
	} else {
		step("realm %q: exists (setup not finished: no administrator has chosen a password yet)", MasterRealmName)
	}

	// 2. Strict settings: MFA for everyone, security e-mails on.
	if created, err := s.ensureMasterSettings(ctx, realm.ID, in.Actor); err != nil {
		return nil, err
	} else if created {
		step("settings: created (MFA required for every account, security e-mails on)")
	}

	// 3. The JWT signing key, needed to sign the admin console's tokens.
	if warning, created, err := s.ensureSigningKey(ctx, realm.ID, in.Actor); err != nil {
		return nil, err
	} else {
		res.SigningKeyWarning = warning
		switch {
		case created:
			step("signing key: created")
		case warning == "":
			step("signing key: exists")
		}
	}

	// 4. Permission catalogue and the two system groups.
	permIDs, readIDs, err := s.ensureAdminPermissions(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	step("permissions: %d admin permissions", len(permIDs))
	admins, err := s.ensureSystemGroup(ctx, realm.ID, AdminGroupName, "Administrators of the instance: every permission", permIDs)
	if err != nil {
		return nil, err
	}
	if _, err := s.ensureSystemGroup(ctx, realm.ID, AuditorGroupName, "Read-only access to the admin console", readIDs); err != nil {
		return nil, err
	}
	step("groups %q and %q: ready (managed by the system)", AdminGroupName, AuditorGroupName)

	// 5. The admin console's OIDC client. An existing one is never changed.
	secret, err := s.ensureAdminClient(ctx, realm.ID, consoleURL, in.Actor)
	if err != nil {
		return nil, err
	}
	if secret != "" {
		res.ClientSecret = secret
		step("client %q: created (redirect URI %s%s, MFA required)", domain.InternalAdminClientID, consoleURL, AdminConsoleCallbackPath)
	} else {
		step("client %q: exists, unchanged (secret not shown again: `idp-admin recover client-secret` makes a new one)", domain.InternalAdminClientID)
	}

	// 6. The first administrator, without password, member of "admins".
	user, err := s.ensurePendingAdmin(ctx, realm.ID, username, email)
	if err != nil {
		return nil, err
	}
	if err := s.addToGroup(ctx, user.ID, admins.ID); err != nil {
		return nil, err
	}
	step("administrator %q <%s>: ready, member of %q", user.Username, user.Email, AdminGroupName)

	// 7. The activation link (shown once, never stored in clear).
	token, expires, err := s.d.PasswordReset.IssueActivationToken(ctx, user, BootstrapActivationTTL, in.Actor)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: activation link: %w", err)
	}
	res.ActivationURL = s.activationURL(realm.Name, token)
	res.ActivationExpires = expires

	s.writeCLIAudit(ctx, realm.ID, "bootstrap", "Realm", realm.ID, in.Actor, map[string]interface{}{
		"admin_user_id": user.ID, "admin_username": user.Username, "client_created": secret != "",
	})
	return res, nil
}

// RecoverAdminInput: `idp-admin recover admin --email ...`.
type RecoverAdminInput struct {
	Email string
	Actor string // "cli:<os user>@<host>"
}

// RecoverAdminResult: the new account and its activation link.
type RecoverAdminResult struct {
	Username          string
	ActivationURL     string
	ActivationExpires time.Time
	AlertedAdmins     int
}

// RecoverAdmin creates a NEW administrator account (never resets an
// existing one) and alerts every administrator by e-mail.
func (s *AdminService) RecoverAdmin(ctx context.Context, in RecoverAdminInput) (*RecoverAdminResult, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(in.Email))
	if err != nil || addr.Name != "" {
		return nil, adminInvalid("email", "a plain e-mail address is required")
	}
	realm, admins, err := s.bootstrappedMaster(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.d.Users.GetByRealmAndEmail(ctx, realm.ID, addr.Address); err == nil {
		return nil, adminConflict("email_taken", "an account of the master realm already uses %s: recovery never "+
			"touches existing accounts, give another address", addr.Address)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}

	// Alert the CURRENT administrators (before the new one joins).
	current, err := s.d.Admin.ActiveGroupMemberIDs(ctx, admins.ID)
	if err != nil {
		return nil, err
	}

	username := "recovery-" + s.d.Now().UTC().Format("20060102-1504")
	for i := 2; ; i++ {
		if _, err := s.d.Users.GetByRealmAndUsername(ctx, realm.ID, username); errors.Is(err, repository.ErrNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		username = fmt.Sprintf("recovery-%s-%d", s.d.Now().UTC().Format("20060102-1504"), i)
	}
	user, err := s.d.Users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: username, Email: addr.Address, Status: domain.UserActive,
	})
	if err != nil {
		return nil, fmt.Errorf("recover: create account: %w", err)
	}
	if err := s.addToGroup(ctx, user.ID, admins.ID); err != nil {
		return nil, err
	}
	token, expires, err := s.d.PasswordReset.IssueActivationToken(ctx, user, BootstrapActivationTTL, in.Actor)
	if err != nil {
		return nil, fmt.Errorf("recover: activation link: %w", err)
	}

	s.writeCLIAudit(ctx, realm.ID, "recovery_admin", "User", user.ID, in.Actor, map[string]interface{}{
		"new_username": username, "email": addr.Address,
	})
	s.alertAdmins(ctx, realm.ID, current, "a new administrator account", in.Actor, username)
	return &RecoverAdminResult{Username: username, ActivationURL: s.activationURL(realm.Name, token),
		ActivationExpires: expires, AlertedAdmins: len(current)}, nil
}

// RecoverClientSecret gives the admin console client a new secret (the old
// one stops working at once) and alerts every administrator.
func (s *AdminService) RecoverClientSecret(ctx context.Context, actor string) (string, int, error) {
	realm, admins, err := s.bootstrappedMaster(ctx)
	if err != nil {
		return "", 0, err
	}
	secret, err := s.d.OIDCClients.RotateSecret(ctx, realm.ID, domain.InternalAdminClientID)
	if err != nil {
		return "", 0, fmt.Errorf("recover: %w", err)
	}
	app, _ := s.d.Clients.GetByRealmAndClientID(ctx, realm.ID, domain.InternalAdminClientID)
	appID := ""
	if app != nil {
		appID = app.ID
	}
	s.writeCLIAudit(ctx, realm.ID, "recovery_client_secret", "ClientApp", appID, actor, nil)
	current, err := s.d.Admin.ActiveGroupMemberIDs(ctx, admins.ID)
	if err != nil {
		return secret, 0, nil // the secret is changed: do not hide it because of the alert
	}
	s.alertAdmins(ctx, realm.ID, current, "a new secret for the admin console", actor, "")
	return secret, len(current), nil
}

// --- helpers --------------------------------------------------------------------

func checkBootstrapAccount(email, username string) (string, string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil || addr.Name != "" {
		return "", "", adminInvalid("email", "a plain e-mail address is required (--email admin@example.com)")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username, _, _ = strings.Cut(addr.Address, "@")
	}
	if err := checkUsername(username); err != nil {
		return "", "", err
	}
	return addr.Address, username, nil
}

func checkConsoleURL(raw string, production bool) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", adminInvalid("admin_url", "the admin console URL must be absolute, without query or fragment (e.g. https://admin.example.com)")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()) && !production:
	default:
		return "", adminInvalid("admin_url", "the admin console URL must use https (http only for localhost in development)")
	}
	return raw, nil
}

func (s *AdminService) ensureMasterSettings(ctx context.Context, realmID, actor string) (bool, error) {
	if _, err := s.d.Settings.GetByRealmID(ctx, realmID); err == nil {
		return false, nil // never change existing settings
	} else if !errors.Is(err, repository.ErrNotFound) {
		return false, err
	}
	st, err := s.d.Settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: realmID})
	if err != nil {
		return false, fmt.Errorf("bootstrap: settings: %w", err)
	}
	yes := true
	stepUpMaxAge := int(AdminConsoleStepUpMaxAge / time.Minute)
	_, err = s.d.Settings.Update(ctx, st.ID, repository.UpdateInstanceSettingsParams{
		MFARequiredGlobally:      &yes,
		MFAStepUpMaxAgeMinutes:   &stepUpMaxAge,
		NotificationEmailEnabled: &yes,
		UpdatedBy:                &actor,
	})
	return true, err
}

// ensureSigningKey creates the realm's JWT key when it has none. With the
// local_dev KeyManager the private key would live in THIS process only (the
// CLI, or idp-admin): the public server could never sign with it. Then no
// key is created and the warning explains what to do.
func (s *AdminService) ensureSigningKey(ctx context.Context, realmID, actor string) (warning string, created bool, err error) {
	keys, err := s.d.KeyRotation.List(ctx, realmID)
	if err != nil {
		return "", false, fmt.Errorf("signing keys: %w", err)
	}
	if slices.ContainsFunc(keys, func(k *domain.SigningKey) bool {
		return k.Status == domain.SigningKeyActive && k.Purpose == domain.SigningKeyPurposeJWT
	}) {
		return "", false, nil
	}
	if s.d.KMSBackend == "local_dev" {
		return "no signing key created: KEYMANAGER_BACKEND=local_dev keeps private keys in the memory of one process. " +
			"Use KEYMANAGER_BACKEND=vault (`make dev` starts Vault), then run this again.", false, nil
	}
	if _, err := s.d.KeyRotation.Rotate(ctx, RotateInput{RealmID: realmID, TriggeredBy: actor, Reason: "realm setup"}); err != nil {
		return "", false, fmt.Errorf("create signing key: %w", err)
	}
	return "", true, nil
}

// ensureAdminPermissions creates the missing permissions of the catalogue
// and returns the ids of all of them, and of the "read" ones.
func (s *AdminService) ensureAdminPermissions(ctx context.Context, realmID string) (all, read []string, err error) {
	for _, p := range AdminPermissions {
		perm, err := s.d.Permissions.GetByRealmAndName(ctx, realmID, p.Name())
		if errors.Is(err, repository.ErrNotFound) {
			perm, err = s.d.Permissions.Create(ctx, repository.CreatePermissionParams{
				RealmID: realmID, Name: p.Name(), Description: p.Description,
				Resource: p.Resource, Action: p.Action, Scope: AdminPermissionScope,
			})
		}
		if err != nil {
			return nil, nil, fmt.Errorf("permission %s: %w", p.Name(), err)
		}
		all = append(all, perm.ID)
		if p.Action == "read" {
			read = append(read, perm.ID)
		}
	}
	return all, read, nil
}

func (s *AdminService) ensureSystemGroup(ctx context.Context, realmID, name, description string, permIDs []string) (*domain.Group, error) {
	g, err := s.d.Groups.GetByRealmAndName(ctx, realmID, name)
	if errors.Is(err, repository.ErrNotFound) {
		g, err = s.d.Groups.Create(ctx, repository.CreateGroupParams{RealmID: realmID, Name: name, Description: description})
	}
	if err != nil {
		return nil, fmt.Errorf("group %s: %w", name, err)
	}
	if err := s.d.Admin.SetGroupPermissions(ctx, g.ID, permIDs); err != nil {
		return nil, fmt.Errorf("group %s permissions: %w", name, err)
	}
	if err := s.d.Admin.SetManagedBy(ctx, "group", g.ID, string(domain.GroupManagedByConfig)); err != nil {
		return nil, fmt.Errorf("group %s: %w", name, err)
	}
	return g, nil
}

// ensureAdminClient creates "sso-admin" when missing and returns its secret;
// an existing client is left exactly as it is ("" returned).
func (s *AdminService) ensureAdminClient(ctx context.Context, realmID, consoleURL, actor string) (string, error) {
	if _, err := s.d.Clients.GetByRealmAndClientID(ctx, realmID, domain.InternalAdminClientID); err == nil {
		return "", nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return "", err
	}
	app, secret, err := s.d.OIDCClients.Create(ctx, OIDCClientInput{
		RealmID:                realmID,
		Name:                   "Admin console",
		ClientID:               domain.InternalAdminClientID,
		RedirectURIs:           []string{consoleURL + AdminConsoleCallbackPath},
		PostLogoutRedirectURIs: []string{consoleURL + "/"},
		Scopes:                 []string{"profile", "email", "offline_access"},
		AllowGroups:            []string{AdminGroupName, AuditorGroupName},
		GrantedBy:              actor,
	})
	if err != nil {
		return "", fmt.Errorf("create client %s: %w", domain.InternalAdminClientID, err)
	}
	config := domain.ClientAppManagedByConfig
	required := domain.ClientAppMFARequired
	accessTokenTTL := int(AdminConsoleAccessTokenTTL / time.Second)
	if _, err := s.d.Clients.Update(ctx, app.ID, repository.UpdateClientAppParams{
		ManagedBy: &config, MFAPolicy: &required, AccessTokenTTL: &accessTokenTTL,
	}); err != nil {
		return "", fmt.Errorf("configure client %s: %w", domain.InternalAdminClientID, err)
	}
	return secret, nil
}

// ensurePendingAdmin returns the account to make administrator: a new one,
// or the not-yet-activated account of a previous, unfinished bootstrap.
func (s *AdminService) ensurePendingAdmin(ctx context.Context, realmID, username, email string) (*domain.User, error) {
	byName, err := s.d.Users.GetByRealmAndUsername(ctx, realmID, username)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	byMail, err := s.d.Users.GetByRealmAndEmail(ctx, realmID, email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	switch {
	case byName == nil && byMail == nil:
		return s.d.Users.Create(ctx, repository.CreateUserParams{
			RealmID: realmID, Username: username, Email: email, Status: domain.UserActive,
		})
	case byName != nil && byMail != nil && byName.ID == byMail.ID && byName.PasswordHash == "":
		return byName, nil // unfinished bootstrap: a new activation link is issued
	default:
		return nil, adminConflict("account_taken", "the username or e-mail is already used by another account of the master realm")
	}
}

func (s *AdminService) addToGroup(ctx context.Context, userID, groupID string) error {
	m, err := s.d.Admin.Memberships(ctx, []string{userID})
	if err != nil {
		return err
	}
	groups := m[userID].GroupIDs
	if slices.Contains(groups, groupID) {
		return nil
	}
	return s.d.Admin.SetUserGroups(ctx, userID, append(groups, groupID))
}

// bootstrappedMaster returns the master realm and its "admins" group, or
// ErrNotBootstrapped.
func (s *AdminService) bootstrappedMaster(ctx context.Context) (*domain.Realm, *domain.Group, error) {
	realm, err := s.d.Realms.GetByName(ctx, MasterRealmName)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, ErrNotBootstrapped
	}
	if err != nil {
		return nil, nil, err
	}
	activated, err := s.d.Admin.CountUsersWithPassword(ctx, realm.ID)
	if err != nil {
		return nil, nil, err
	}
	if activated == 0 {
		return nil, nil, ErrNotBootstrapped
	}
	admins, err := s.d.Groups.GetByRealmAndName(ctx, realm.ID, AdminGroupName)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, ErrNotBootstrapped
	}
	return realm, admins, err
}

// writeCLIAudit records a bootstrap/recovery step: level critical, the OS
// user and host in details (no user id: nobody was signed in).
func (s *AdminService) writeCLIAudit(ctx context.Context, realmID, action, resourceType, resourceID, actor string, details map[string]interface{}) {
	if s.d.Audit == nil {
		return
	}
	d := map[string]interface{}{"triggered_by": actor}
	for k, v := range details {
		d[k] = v
	}
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      realmID,
		Action:       "admin." + action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Level:        domain.AuditLogCritical,
		Status:       domain.AuditLogSuccess,
		Details:      d,
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "admin audit write failed", "action", action, "error", err)
	}
}

// alertAdmins e-mails every listed administrator about a recovery.
func (s *AdminService) alertAdmins(ctx context.Context, realmID string, userIDs []string, kind, actor, account string) {
	for _, id := range userIDs {
		s.d.Notifier.Notify(ctx, domain.NotificationEvent{
			Kind:            domain.NotificationAdminRecovery,
			RealmID:         realmID,
			UserID:          id,
			OccurredAt:      s.d.Now(),
			RecoveryKind:    kind,
			RecoveryActor:   actor,
			RecoveryAccount: account,
		})
	}
}
