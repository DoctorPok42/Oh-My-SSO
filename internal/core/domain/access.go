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
}

const InternalAdminClientID = "sso-admin"
