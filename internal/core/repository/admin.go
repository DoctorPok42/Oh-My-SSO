package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// AdminRepository groups the queries and grant changes that only the Admin
// API needs (Step 14): searches with filters and pagination, counters for the
// dashboard, and "replace the whole set" updates of memberships and grants.
//
// It is a separate interface on purpose: the per-entity repositories stay
// small, and the in-memory fakes of the existing tests do not have to
// implement admin-only methods.
type AdminRepository interface {
	// --- realms ---
	ListRealms(ctx context.Context) ([]*domain.Realm, error)
	// CreateSystemRealm creates the "master" realm (is_system_realm = true).
	// RealmRepository.Create refuses reserved names; this is the only way in.
	CreateSystemRealm(ctx context.Context, p CreateRealmParams) (*domain.Realm, error)

	// --- users ---
	SearchUsers(ctx context.Context, f UserSearch) ([]*domain.User, int, error)
	// UsersByIDs loads users of any realm (actors of audit entries may be
	// admins of the master realm).
	UsersByIDs(ctx context.Context, ids []string) ([]*domain.User, error)
	SetUserProfile(ctx context.Context, userID string, profile map[string]interface{}) error
	// CountUsersWithPassword: accounts of the realm that chose a password
	// (activated). The bootstrap of the master realm runs while it is 0.
	CountUsersWithPassword(ctx context.Context, realmID string) (int, error)
	Memberships(ctx context.Context, userIDs []string) (map[string]Memberships, error)
	SetUserGroups(ctx context.Context, userID string, groupIDs []string) error
	SetUserRoles(ctx context.Context, userID string, roleIDs []string) error
	// ActiveGroupMemberIDs: members of the group whose account is active.
	ActiveGroupMemberIDs(ctx context.Context, groupID string) ([]string, error)
	// MemberCounts: number of users per group and per role of a realm.
	MemberCounts(ctx context.Context, realmID string) (groups, roles map[string]int, err error)
	// UsersWithActiveMFA: which of these users have at least one active factor.
	UsersWithActiveMFA(ctx context.Context, userIDs []string) (map[string]bool, error)
	// LastSuccessfulLogins: time of the last successful password check per user.
	LastSuccessfulLogins(ctx context.Context, userIDs []string) (map[string]time.Time, error)

	// --- roles, groups, permissions ---
	RoleGrants(ctx context.Context, roleID string) (Grants, error)
	GroupGrants(ctx context.Context, groupID string) (Grants, error)
	SetRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error
	SetGroupPermissions(ctx context.Context, groupID string, permissionIDs []string) error
	SetRoleClientScopes(ctx context.Context, roleID string, scopeIDs []string) error
	SetGroupClientScopes(ctx context.Context, groupID string, scopeIDs []string) error
	// SetManagedBy marks a role or a group as managed by "ui" or "config"
	// (kind: "role" or "group"). Config-managed objects are read-only in the
	// Admin API.
	SetManagedBy(ctx context.Context, kind, id, managedBy string) error

	// --- clients ---
	ClientGrants(ctx context.Context, clientRef string) (ClientGrants, error)
	SetClientRoles(ctx context.Context, clientRef string, roleIDs []string, grantedBy string) error
	SetClientGroups(ctx context.Context, clientRef string, groupIDs []string, grantedBy string) error
	SetClientScopes(ctx context.Context, clientRef string, scopes []ScopeMapping) error
	// ScopeUsage: number of (not deleted) clients mapping each client scope.
	ScopeUsage(ctx context.Context, realmID string) (map[string]int, error)
	CountActiveClients(ctx context.Context, realmID string) (int, error)

	// --- sessions ---
	SearchSessions(ctx context.Context, f SessionSearch) ([]*domain.Session, int, error)
	// SessionClients: the clients (ClientApp.ID) holding a live token for
	// each session.
	SessionClients(ctx context.Context, sessionIDs []string, now time.Time) (map[string][]string, error)

	// --- audit log, sign-ins ---
	SearchAuditLogs(ctx context.Context, f AuditSearch) ([]*domain.AuditLog, int, error)
	LoginCounts(ctx context.Context, realmID string, since time.Time) (success, failure int, err error)
	LoginAttemptsByUser(ctx context.Context, userID string, limit int) ([]*domain.LoginAttempt, error)

	// --- MFA ---
	// MFACoverage: active users of the realm, and how many have an active factor.
	MFACoverage(ctx context.Context, realmID string) (enrolled, total int, err error)

	// --- timeouts ---
	ListTimeouts(ctx context.Context, realmID string) ([]*domain.Timeout, error)
}

// Page of results: Offset rows skipped, at most Limit returned.
type Page struct {
	Offset int
	Limit  int
}

// UserSearch filters users of one realm.
type UserSearch struct {
	RealmID string
	Query   string            // substring of username or e-mail, case-insensitive
	Status  domain.UserStatus // empty: any
	GroupID string            // empty: any
	RoleID  string            // empty: any
	Page
}

// SessionSearch filters the live sessions of one realm: status active, not
// past expires_at, and used after IdleSince.
type SessionSearch struct {
	RealmID   string
	UserID    string // empty: any
	ClientRef string // empty: any; else sessions with a live token for it
	Now       time.Time
	IdleSince time.Time
	Page
}

// AuditSearch filters the audit log of one realm, newest first.
type AuditSearch struct {
	RealmID string
	// UserID matches entries done by the user OR about the user.
	UserID string
	// ClientRef matches entries about a client (resource ClientApp).
	ClientRef string
	Action    string                // exact action name; empty: any
	Status    domain.AuditLogStatus // empty: any
	From, To  time.Time             // zero: unbounded
	Page
}

// Memberships of a user: ids of its groups and roles.
type Memberships struct {
	GroupIDs []string
	RoleIDs  []string
}

// Grants of a role or a group.
type Grants struct {
	PermissionIDs  []string
	ClientScopeIDs []string
}

// ClientGrants: who may use a client, and its client scopes.
type ClientGrants struct {
	RoleIDs  []string
	GroupIDs []string
	Scopes   []ScopeMapping
}

// ScopeMapping links a client to a client scope. Required scopes are always
// granted to the client; optional ones only when requested.
type ScopeMapping struct {
	ClientScopeID string
	Required      bool
}
