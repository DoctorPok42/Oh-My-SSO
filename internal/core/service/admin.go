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
)


const MasterRealmName = "master"

// AdminActor is the administrator behind an Admin API call.
type AdminActor struct {
	UserID    string // user of the master realm
	Username  string
	RealmID   string // the master realm
	IPAddress string
	UserAgent string
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
}

func (e *AdminError) Error() string { return "admin: " + e.Code + ": " + e.Message }

func adminInvalid(field, format string, a ...any) error {
	return &AdminError{Kind: AdminInvalid, Code: "invalid_request", Field: field, Message: fmt.Sprintf(format, a...)}
}

func adminNotFound(what string) error {
	return &AdminError{Kind: AdminNotFound, Code: "not_found", Message: what + " not found"}
}

func adminConflict(code, format string, a ...any) error {
	return &AdminError{Kind: AdminConflict, Code: code, Message: fmt.Sprintf(format, a...)}
}

func adminRefused(code, format string, a ...any) error {
	return &AdminError{Kind: AdminRefused, Code: code, Message: fmt.Sprintf(format, a...)}
}

var errManagedByConfig = &AdminError{Kind: AdminRefused, Code: "managed_by_config",
	Message: "this object is managed by the configuration file (or by the system): it is read-only here"}

// asAdminError turns the errors of the other services into AdminErrors
// when they are the caller's fault.
func asAdminError(err error) error {
	var ae *AdminError
	var pe *PasswordPolicyError
	var tr *TimeoutRefusal
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ae):
		return ae
	case errors.Is(err, repository.ErrNotFound):
		return adminNotFound("object")
	case errors.Is(err, ErrManagedByConfig):
		return errManagedByConfig
	case errors.Is(err, ErrInvalidClientConfig), errors.Is(err, ErrInvalidMFAPolicy),
		errors.Is(err, ErrUnknownMFAPolicy), errors.Is(err, ErrUnknownMFAMethod):
		msg := err.Error()
		for _, p := range []string{"service: invalid client configuration: ", "service: "} {
			msg = strings.TrimPrefix(msg, p)
		}
		return &AdminError{Kind: AdminInvalid, Code: "invalid_request", Message: msg}
	case errors.As(err, &pe):
		return &AdminError{Kind: AdminInvalid, Code: "password_policy", Message: pe.Error()}
	case errors.As(err, &tr):
		return timeoutAdminError(tr)
	}
	return err
}

// AdminDeps groups what the admin service needs.
type AdminDeps struct {
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

	// PublicURL of cmd/idp: base of activation links.
	PublicURL string
	// EmailEnabled: invitation e-mails can leave the server.
	EmailEnabled bool
	// KMSBackend: "local_dev" keys live in one process only (see CreateRealm).
	KMSBackend string

	Now    func() time.Time
	Logger *slog.Logger
}

// AdminService implements the Admin API operations.
type AdminService struct {
	d AdminDeps
}

func NewAdminService(d AdminDeps) *AdminService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Notifier == nil {
		d.Notifier = NopNotifier{}
	}
	d.PublicURL = strings.TrimRight(d.PublicURL, "/")
	return &AdminService{d: d}
}

// auditAdmin writes one AuditLog entry for an admin action, in the realm
// it changed. A failed write is logged, never returned: the change itself
// is done, and refusing to report it would be worse.
func (s *AdminService) auditAdmin(ctx context.Context, actor AdminActor, realmID, action, resourceType, resourceID string,
	level domain.AuditLogLevel, details map[string]interface{}) {
	if s.d.Audit == nil {
		return
	}
	d := map[string]interface{}{"admin_realm": MasterRealmName, "admin_username": actor.Username}
	maps.Copy(d, details)
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      realmID,
		UserID:       actor.UserID,
		Action:       "admin." + action,
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
		return nil, adminNotFound("realm")
	}
	return r, err
}

func (s *AdminService) userInRealm(ctx context.Context, realmID, userID string) (*domain.User, error) {
	u, err := s.d.Users.GetByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && (u.RealmID != realmID || u.DeletedAt != nil)) {
		return nil, adminNotFound("user")
	}
	return u, err
}

func (s *AdminService) clientInRealm(ctx context.Context, realmID, id string) (*domain.ClientApp, error) {
	c, err := s.d.Clients.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && (c.RealmID != realmID || c.IsDeleted())) {
		return nil, adminNotFound("client")
	}
	return c, err
}

func (s *AdminService) roleInRealm(ctx context.Context, realmID, id string) (*domain.Role, error) {
	r, err := s.d.Roles.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && r.RealmID != realmID) {
		return nil, adminNotFound("role")
	}
	return r, err
}

func (s *AdminService) groupInRealm(ctx context.Context, realmID, id string) (*domain.Group, error) {
	g, err := s.d.Groups.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && g.RealmID != realmID) {
		return nil, adminNotFound("group")
	}
	return g, err
}

func (s *AdminService) scopeInRealm(ctx context.Context, realmID, id string) (*domain.ClientScope, error) {
	cs, err := s.d.Scopes.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && cs.RealmID != realmID) {
		return nil, adminNotFound("client scope")
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
				return nil, adminInvalid(field, "unknown id %q in %s", id, field)
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
			return adminNotFound("permission")
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
