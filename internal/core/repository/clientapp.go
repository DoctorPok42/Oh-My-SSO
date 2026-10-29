package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type ClientRepository interface {
	Create(ctx context.Context, p CreateClientAppParams) (*domain.ClientApp, error)
	GetByID(ctx context.Context, id string) (*domain.ClientApp, error)
	GetByRealmAndClientID(ctx context.Context, realmID, clientID string) (*domain.ClientApp, error)
	GetByRealmAndEntityID(ctx context.Context, realmID, entityID string) (*domain.ClientApp, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.ClientApp, error)
	Update(ctx context.Context, id string, p UpdateClientAppParams) (*domain.ClientApp, error)
	Delete(ctx context.Context, id string) error

	// ListScopes returns the ClientScopes mapped to the client
	// (ClientScopeMapping): the custom scopes it may ask for.
	ListScopes(ctx context.Context, clientRef string) ([]*domain.ClientScope, error)
	// GrantRole and GrantGroup let the members of a role or group use the
	// client (ClientRole / ClientGroup). Granting twice is not an error.
	GrantRole(ctx context.Context, clientRef, roleID, grantedBy string) error
	GrantGroup(ctx context.Context, clientRef, groupID, grantedBy string) error
	// MapScope lets the client ask for a ClientScope (ClientScopeMapping).
	// Mapping twice is not an error.
	MapScope(ctx context.Context, clientRef, clientScopeID string) error
}

type CreateClientAppParams struct {
	RealmID      string
	Name         string
	Protocol     domain.ClientAppProtocol
	OwnerAdminID string
}

type UpdateClientAppParams struct {
	ManagedBy    *domain.ClientAppManagedBy
	Name         *string
	Status       *domain.ClientAppStatus
	OwnerAdminID *string

	ClientID                *string
	ClientSecretHash        *string
	ClientType              *domain.ClientAppType
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	AllowedGrantTypes       []string
	AllowedScopes           []string
	TokenEndpointAuthMethod *string
	IDTokenSignedAlg        *string
	AccessTokenTTL          *int
	RefreshTokenTTL         *int
	IDTokenTTL              *int
	RequirePKCE             *bool

	EntityID            *string
	ACSURL              *string
	SLOURL              *string
	ClientCertificates  []map[string]interface{}
	NameIDFormat        *string
	WantAssertionSigned *bool
	WantResponseSigned  *bool
	DefaultRelayState   *string

	AttributeMappings map[string]interface{}
	RequireConsent    *bool
	MetadataURL       *string

	// Changing either value changes every subject this client receives.
	SubjectType      *domain.ClientAppSubjectType
	SectorIdentifier *string

	MFAPolicy *domain.ClientAppMFAPolicy
	// nil: unchanged. Empty non-nil slice: clear (any method allowed).
	MFAAllowedMethods []domain.MfaMethodType
}
