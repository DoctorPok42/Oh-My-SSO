package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)


const MasterRealmName = "master"

// AdminActor is the administrator behind an Admin API call.
type AdminActor struct {
	UserID    string // user of the master realm
	Username  string
	RealmID   string // the master realm
	IPAddress string
	UserAgent string
	// SessionID: the session the call comes from (bulk revocations leave it
	// out). Empty: not an Admin API call.
	SessionID string
}

// By is how other services record the actor ("user:<id>", like the CLI's
// "cli:<os user>").
func (a AdminActor) By() string { return "user:" + a.UserID }

// AdminErrorKind tells the HTTP layer which status to answer.
type AdminErrorKind int

const (
	AdminInvalid  AdminErrorKind = iota + 1 // 400: the request is wrong
	AdminNotFound                           // 404
	AdminConflict                           // 409: already exists, in use...
	AdminRefused                            // 409: a guardrail said no (last admin, managed by config...)
)

// AdminError is a refusal the administrator can act upon. Code is stable
// (for the UI), Message is a sentence for humans.
type AdminError struct {
	Kind    AdminErrorKind
	Code    string
	Message string
	Field   string // optional: the input field at fault
	// Text, when its key is set, is the translatable form of Message: the
	// Admin API answers in the console's language (adminapi.writeServiceError).
	Text i18n.Text
}

// adminText is an AdminError whose sentence is translatable. Message is the
// English text, for the logs and for the clients that do not translate.
func adminText(kind AdminErrorKind, code, field string, t i18n.Text) error {
	var english *i18n.Localizer // nil: English
	return &AdminError{Kind: kind, Code: code, Field: field, Message: english.Text(t), Text: t}
}

func (e *AdminError) Error() string { return "admin: " + e.Code + ": " + e.Message }

func adminInvalid(field string, t i18n.Text) error {
	return adminText(AdminInvalid, "invalid_request", field, t)
}

// The refusals of the terminal (idp-admin bootstrap) stay in English: the
// console translates the refusals of the Admin API, not the CLI's output.
func adminInvalidEN(field, format string, a ...any) error {
	return &AdminError{Kind: AdminInvalid, Code: "invalid_request", Field: field, Message: fmt.Sprintf(format, a...)}
}

func adminConflictEN(code, format string, a ...any) error {
	return &AdminError{Kind: AdminConflict, Code: code, Message: fmt.Sprintf(format, a...)}
}

func adminNotFound(t i18n.Text) error {
	return adminText(AdminNotFound, "not_found", "", t)
}

func adminConflict(code string, t i18n.Text) error {
	return adminText(AdminConflict, code, "", t)
}

func adminRefused(code string, t i18n.Text) error {
	return adminText(AdminRefused, code, "", t)
}

var errManagedByConfig = &AdminError{Kind: AdminRefused, Code: "managed_by_config",
	Message: "this object is managed by the configuration file (or by the system): it is read-only here",
	Text: i18n.M("admin.error.managed_by_config", "this object is managed by the configuration file (or by the system): it is read-only here")}

// asAdminError turns the errors of the other services into AdminErrors
// when they are the caller's fault.
func asAdminError(err error) error {
	var ae *AdminError
	var pe *PasswordPolicyError
	var tr *TimeoutRefusal
	var te *textError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ae):
		return ae
	case errors.Is(err, repository.ErrNotFound):
		return adminNotFound(i18n.M("admin.error.not_found.object", "object not found"))
	case errors.Is(err, ErrManagedByConfig):
		return errManagedByConfig
	case errors.As(err, &te):
		return &AdminError{Kind: AdminInvalid, Code: "invalid_request", Message: englishOf(te.Text), Text: te.Text}
	case errors.Is(err, ErrInvalidClientConfig), errors.Is(err, ErrInvalidMFAPolicy),
		errors.Is(err, ErrUnknownMFAPolicy), errors.Is(err, ErrUnknownMFAMethod):
		msg := err.Error()
		for _, p := range []string{"service: invalid client configuration: ", "service: "} {
			msg = strings.TrimPrefix(msg, p)
		}
		return &AdminError{Kind: AdminInvalid, Code: "invalid_request", Message: msg}
	case errors.As(err, &pe):
		return &AdminError{Kind: AdminInvalid, Code: "password_policy", Message: pe.Error(), Text: passwordText(pe)}
	case errors.As(err, &tr):
		return timeoutAdminError(tr)
	}
	return err
}

// AdminDeps groups what the admin service needs.
type AdminDeps struct {
	// Tx makes the creation and the change of an account one transaction
	// each. Required: repository.NoTransaction{} for in-memory stores.
	Tx          repository.Transactor
	Realms      repository.RealmRepository
	Users       repository.UserRepository
	Clients     repository.ClientRepository
	Scopes      repository.ClientScopeRepository
	Roles       repository.RoleRepository
	Groups      repository.GroupRepository
	Permissions repository.PermissionRepository
	Settings    repository.InstanceSettingsRepository
	Audit       repository.AuditLogRepository
	Access      repository.AccessRepository
	MfaMethods  repository.MfaMethodRepository
	Admin       repository.AdminRepository

	Sessions      *SessionService
	KeyRotation   *KeyRotationService
	MFA           *MFAService
	MFAPolicy     *MFAPolicyService
	PasswordReset *PasswordResetService
	Lockout       *LockoutService
	OIDCClients   *OIDCClientService
	SAMLClients   *SAMLClientService
	Timeouts      *TimeoutService
	Notifier      Notifier // nil: no e-mail
	TrustedDevices *TrustedDeviceService
	// Languages: the languages the IdP can show (default_locale must be one
	// of them). nil: the embedded ones.
	Languages *i18n.Bundle

	// UserImports: the imports of CSV files of users. nil outside idp-admin
	// (the CLI does not import).
	UserImports repository.UserImportRepository
	// BulkJobs: the bulk actions of the console, run in the background. nil
	// outside idp-admin.
	BulkJobs repository.BulkJobRepository
	// Outbox: the e-mails of the accounts (delivery status, "send again").
	// nil: not shown.
	Outbox repository.EmailOutboxRepository
	// EmailVerification: "send a verification e-mail". nil: refused.
	EmailVerification *EmailVerificationService

	// PublicURL of cmd/idp: base of activation links.
	PublicURL string
	// ConsoleURL of the admin console: the link in the e-mail at the end of
	// an import. "": the e-mail has no link.
	ConsoleURL string
	// EmailEnabled: invitation e-mails can leave the server.
	EmailEnabled bool
	// KMSBackend: "local_dev" keys live in one process only (see CreateRealm).
	KMSBackend string

	Now    func() time.Time
	Logger *slog.Logger
}

// AdminService implements the Admin API operations.
type AdminService struct {
	d       AdminDeps
	imports *jobRunner
	bulks   *jobRunner
}

func NewAdminService(d AdminDeps) *AdminService {
	if d.Tx == nil {
		// Never quietly without: an account half created or half changed is B-15.
		panic("service: AdminDeps.Tx is required (repository.NoTransaction{} for in-memory stores)")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Notifier == nil {
		d.Notifier = NopNotifier{}
	}
	d.Audit = BatchedAuditLog(d.Audit) // one entry per bulk action
	if d.Languages == nil {
		d.Languages = i18n.MustDefault()
	}
	d.PublicURL = strings.TrimRight(d.PublicURL, "/")
	d.ConsoleURL = strings.TrimRight(d.ConsoleURL, "/")
	return &AdminService{d: d, imports: newJobRunner(), bulks: newJobRunner()}
}

// auditAdmin writes one AuditLog entry for an admin action, in the realm
// it changed. A failed write is logged, never returned: the change itself
// is done, and refusing to report it would be worse. The user it is about
// is the resource when that is a User; auditAdminAbout names it otherwise.
func (s *AdminService) auditAdmin(ctx context.Context, actor AdminActor, realmID, action, resourceType, resourceID string,
	level domain.AuditLogLevel, details map[string]interface{}) {
	s.auditAdminAbout(ctx, actor, realmID, "", action, resourceType, resourceID, level, details)
}

// auditAdminAbout is auditAdmin for an action about a user whose resource
// is not the User itself (one of their sessions, a timeout on them...).
func (s *AdminService) auditAdminAbout(ctx context.Context, actor AdminActor, realmID, targetUserID, action, resourceType, resourceID string,
	level domain.AuditLogLevel, details map[string]interface{}) {
	if s.d.Audit == nil {
		return
	}
	d := map[string]interface{}{"admin_realm": MasterRealmName, "admin_username": actor.Username}
	maps.Copy(d, details)
	if op := bulkOperation(ctx); op != "" {
		d["operation_id"] = op
	}
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      realmID,
		UserID:       actor.UserID,
		ActorType:    domain.AuditActorAdmin,
		TargetUserID: targetUserID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    actor.IPAddress,
		UserAgent:    actor.UserAgent,
		Level:        level,
		Status:       domain.AuditLogSuccess,
		Details:      d,
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "admin audit write failed", "action", action, "realm_id", realmID, "error", err)
	}
}


// RealmByName loads an existing realm (active or not).
func (s *AdminService) RealmByName(ctx context.Context, name string) (*domain.Realm, error) {
	r, err := s.d.Realms.GetByName(ctx, name)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.realm", "realm not found"))
	}
	return r, err
}

func (s *AdminService) userInRealm(ctx context.Context, realmID, userID string) (*domain.User, error) {
	u, err := s.d.Users.GetByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && (u.RealmID != realmID || u.DeletedAt != nil)) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.user", "user not found"))
	}
	return u, err
}

func (s *AdminService) clientInRealm(ctx context.Context, realmID, id string) (*domain.ClientApp, error) {
	c, err := s.d.Clients.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && (c.RealmID != realmID || c.IsDeleted())) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.client", "client not found"))
	}
	return c, err
}

func (s *AdminService) roleInRealm(ctx context.Context, realmID, id string) (*domain.Role, error) {
	r, err := s.d.Roles.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && r.RealmID != realmID) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.role", "role not found"))
	}
	return r, err
}

func (s *AdminService) groupInRealm(ctx context.Context, realmID, id string) (*domain.Group, error) {
	g, err := s.d.Groups.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && g.RealmID != realmID) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.group", "group not found"))
	}
	return g, err
}

func (s *AdminService) scopeInRealm(ctx context.Context, realmID, id string) (*domain.ClientScope, error) {
	cs, err := s.d.Scopes.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && cs.RealmID != realmID) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.client_scope", "client scope not found"))
	}
	return cs, err
}

// checkIDs verifies every id names an object of the realm (a role id of
// realm A must never be granted in realm B).
func (s *AdminService) checkIDs(ctx context.Context, field string, ids []string, get func(context.Context, string) error) ([]string, error) {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || slices.Contains(out, id) {
			continue
		}
		if err := get(ctx, id); err != nil {
			var ae *AdminError
			if errors.As(err, &ae) && ae.Kind == AdminNotFound {
				return nil, adminInvalid(field, i18n.M("admin.error.unknown_id", "unknown id \"{id}\" in {field}", "id", id, "field", field))
			}
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func (s *AdminService) checkRoleIDs(ctx context.Context, realmID string, ids []string) ([]string, error) {
	return s.checkIDs(ctx, "role_ids", ids, func(ctx context.Context, id string) error {
		_, err := s.roleInRealm(ctx, realmID, id)
		return err
	})
}

func (s *AdminService) checkGroupIDs(ctx context.Context, realmID string, ids []string) ([]string, error) {
	return s.checkIDs(ctx, "group_ids", ids, func(ctx context.Context, id string) error {
		_, err := s.groupInRealm(ctx, realmID, id)
		return err
	})
}

func (s *AdminService) checkScopeIDs(ctx context.Context, realmID string, ids []string) ([]string, error) {
	return s.checkIDs(ctx, "client_scope_ids", ids, func(ctx context.Context, id string) error {
		_, err := s.scopeInRealm(ctx, realmID, id)
		return err
	})
}

func (s *AdminService) checkPermissionIDs(ctx context.Context, realmID string, ids []string) ([]string, error) {
	return s.checkIDs(ctx, "permission_ids", ids, func(ctx context.Context, id string) error {
		p, err := s.d.Permissions.GetByID(ctx, id)
		if errors.Is(err, repository.ErrNotFound) || (err == nil && p.RealmID != realmID) {
			return adminNotFound(i18n.M("admin.error.not_found.permission", "permission not found"))
		}
		return err
	})
}

// NameRef is an object shown by its name, with its id for links.
type NameRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// namedRefs: ids with their already loaded names, sorted by name.
func namedRefs(ids []string, names map[string]string) []NameRef {
	out := make([]NameRef, 0, len(ids))
	for _, id := range ids {
		if n, ok := names[id]; ok {
			out = append(out, NameRef{ID: id, Name: n})
		}
	}
	slices.SortFunc(out, func(a, b NameRef) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// activationURL is the link of a one-time "choose your password" token.
// The token goes after "#": browsers never send that part to the server.
func (s *AdminService) activationURL(realmName, token string) string {
	return s.d.PublicURL + "/r/" + realmName + "/auth/reset-password#token=" + token
}
