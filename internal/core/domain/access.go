package domain

type AccessSourceKind string

const (
	AccessSourceRole  AccessSourceKind = "role"
	AccessSourceGroup AccessSourceKind = "group"
)

type AccessSource struct {
	Kind         AccessSourceKind
	ID           string
	RealmID      string
	Name         string
	Active       bool
	Permissions  []*Permission
	ClientScopes []*ClientScope
}

type UserAccess struct {
	UserID  string
	RealmID string
	Status  UserStatus
	Roles   []AccessSource
	Groups  []AccessSource
}

type ClientAccessPolicy struct {
	ClientRef string // ClientApp.ID (internal UUID), never the public client_id
	RealmID   string
	Status    ClientAppStatus
	RoleIDs   []string
	GroupIDs  []string
	ScopeIDs  []string
	// RequiredScopeIDs (Step 14): scopes mapped as "required" on the client.
	// They are part of every assertion for this client (when the user is
	// entitled to them), requested or not. The others are optional: only
	// included when the client asks for them.
	RequiredScopeIDs []string
}

const InternalAdminClientID = "sso-admin"
