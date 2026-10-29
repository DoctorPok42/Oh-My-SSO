package domain

import "time"

type ClientAppProtocol string

const (
	ClientAppProtocolOIDC  ClientAppProtocol = "oidc"
	ClientAppProtocolSAML2 ClientAppProtocol = "saml2"
)

type ClientAppStatus string

const (
	ClientAppActive    ClientAppStatus = "active"
	ClientAppInactive  ClientAppStatus = "inactive"
	ClientAppSuspended ClientAppStatus = "suspended"
)

type ClientAppManagedBy string

const (
	ClientAppManagedByUI     ClientAppManagedBy = "ui"
	ClientAppManagedByConfig ClientAppManagedBy = "config"
)

type ClientAppType string

const (
	ClientAppTypeConfidential ClientAppType = "confidential"
	ClientAppTypePublic       ClientAppType = "public"
)

// ClientAppSubjectType decides which subject identifier a client receives.
type ClientAppSubjectType string

const (
	// ClientAppSubjectPublic: every client receives User.ID.
	ClientAppSubjectPublic ClientAppSubjectType = "public"
	// ClientAppSubjectPairwise: each sector receives its own, non-correlatable
	// identifier (OIDC Core §8.1).
	ClientAppSubjectPairwise ClientAppSubjectType = "pairwise"
)

// ClientAppMFAPolicy: see ent/schema/clientapp.go. The strictest of the
// realm, client and role policies always wins.
type ClientAppMFAPolicy string

const (
	ClientAppMFAInherit  ClientAppMFAPolicy = "inherit"
	ClientAppMFARequired ClientAppMFAPolicy = "required"
)

type ClientApp struct {
	ID           string
	RealmID      string
	ManagedBy    ClientAppManagedBy
	Name         string
	Protocol     ClientAppProtocol
	Status       ClientAppStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    time.Time
	OwnerAdminID string

	ClientID                string
	ClientSecretHash        string
	ClientType              ClientAppType
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	AllowedGrantTypes       []string
	AllowedScopes           []string
	TokenEndpointAuthMethod string
	IDTokenSignedAlg        string
	AccessTokenTTL          int
	RefreshTokenTTL         int
	IDTokenTTL              int
	RequirePKCE             bool

	EntityID            string
	ACSURL              string
	SLOURL              string
	ClientCertificates  []map[string]interface{}
	NameIDFormat        string
	WantAssertionSigned bool
	WantResponseSigned  bool
	DefaultRelayState   string

	AttributeMappings map[string]interface{}
	RequireConsent    bool
	MetadataURL       string

	SubjectType      ClientAppSubjectType
	SectorIdentifier string // empty: ClientApp.ID is used as the sector

	MFAPolicy         ClientAppMFAPolicy
	MFAAllowedMethods []MfaMethodType // empty: any method
}

func (c *ClientApp) IsDeleted() bool {
	return !c.DeletedAt.IsZero()
}
