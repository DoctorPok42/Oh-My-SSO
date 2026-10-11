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

	// --- OIDC ---
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

	// --- SAML ---
	EntityID            string
	ACSURL              string
	SLOURL              string
	ClientCertificates  []map[string]interface{}
	NameIDFormat        string
	WantAssertionSigned bool
	WantResponseSigned  bool
	DefaultRelayState   string

	// --- Common ---
	AttributeMappings map[string]interface{}
	RequireConsent    bool
	MetadataURL       string

	// --- Subject identifier ---
	SubjectType      ClientAppSubjectType
	SectorIdentifier string // empty: ClientApp.ID is used as the sector
}

func (c *ClientApp) IsDeleted() bool {
	return !c.DeletedAt.IsZero()
}
