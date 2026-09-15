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

	// --- OIDC ---
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

	// --- SAML ---
	EntityID            *string
	ACSURL              *string
	SLOURL              *string
	ClientCertificates  []map[string]interface{}
	NameIDFormat        *string
	WantAssertionSigned *bool
	WantResponseSigned  *bool
	DefaultRelayState   *string

	// --- Common ---
	AttributeMappings map[string]interface{}
	RequireConsent    *bool
	MetadataURL       *string
}
