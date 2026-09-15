package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/clientapp"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entClientAppRepository struct {
	client *ent.Client
}

func NewClientRepository(client *ent.Client) repository.ClientRepository {
	return &entClientAppRepository{client: client}
}

func (r *entClientAppRepository) Create(ctx context.Context, p repository.CreateClientAppParams) (*domain.ClientApp, error) {
	e, err := r.client.ClientApp.
		Create().
		SetRealmID(p.RealmID).
		SetName(p.Name).
		SetProtocol(entschema.ClientAppProtocol(p.Protocol)).
		SetNillableOwnerAdminID(nonEmpty(p.OwnerAdminID)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientApp(e), nil
}

func (r *entClientAppRepository) GetByID(ctx context.Context, id string) (*domain.ClientApp, error) {
	e, err := r.client.ClientApp.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainClientApp(e), nil
}

func (r *entClientAppRepository) GetByRealmAndClientID(ctx context.Context, realmID, clientID string) (*domain.ClientApp, error) {
	e, err := r.client.ClientApp.
		Query().
		Where(clientapp.RealmID(realmID), clientapp.ClientID(clientID)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientApp(e), nil
}

func (r *entClientAppRepository) GetByRealmAndEntityID(ctx context.Context, realmID, entityID string) (*domain.ClientApp, error) {
	e, err := r.client.ClientApp.
		Query().
		Where(clientapp.RealmID(realmID), clientapp.EntityID(entityID)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientApp(e), nil
}

func (r *entClientAppRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.ClientApp, error) {
	rows, err := r.client.ClientApp.
		Query().
		Where(clientapp.RealmID(realmID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ClientApp, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainClientApp(e))
	}
	return out, nil
}

func (r *entClientAppRepository) Update(ctx context.Context, id string, p repository.UpdateClientAppParams) (*domain.ClientApp, error) {
	builder := r.client.ClientApp.UpdateOneID(id)

	if p.ManagedBy != nil {
		builder = builder.SetManagedBy(entschema.ClientAppManagedBy(*p.ManagedBy))
	}
	if p.Name != nil {
		builder = builder.SetName(*p.Name)
	}
	if p.Status != nil {
		builder = builder.SetStatus(entschema.ClientAppStatus(*p.Status))
	}
	builder = builder.SetNillableOwnerAdminID(p.OwnerAdminID)

	// --- OIDC ---
	builder = builder.SetNillableClientID(p.ClientID)
	builder = builder.SetNillableClientSecretHash(p.ClientSecretHash)
	if p.ClientType != nil {
		builder = builder.SetClientType(entschema.ClientAppType(*p.ClientType))
	}
	if p.RedirectURIs != nil {
		builder = builder.SetRedirectUris(p.RedirectURIs)
	}
	if p.PostLogoutRedirectURIs != nil {
		builder = builder.SetPostLogoutRedirectUris(p.PostLogoutRedirectURIs)
	}
	if p.AllowedGrantTypes != nil {
		builder = builder.SetAllowedGrantTypes(p.AllowedGrantTypes)
	}
	if p.AllowedScopes != nil {
		builder = builder.SetAllowedScopes(p.AllowedScopes)
	}
	builder = builder.SetNillableTokenEndpointAuthMethod(p.TokenEndpointAuthMethod)
	builder = builder.SetNillableIDTokenSignedAlg(p.IDTokenSignedAlg)
	builder = builder.SetNillableAccessTokenTTL(p.AccessTokenTTL)
	builder = builder.SetNillableRefreshTokenTTL(p.RefreshTokenTTL)
	builder = builder.SetNillableIDTokenTTL(p.IDTokenTTL)
	builder = builder.SetNillableRequirePkce(p.RequirePKCE)

	// --- SAML ---
	builder = builder.SetNillableEntityID(p.EntityID)
	builder = builder.SetNillableAcsURL(p.ACSURL)
	builder = builder.SetNillableSloURL(p.SLOURL)
	if p.ClientCertificates != nil {
		builder = builder.SetClientCertificates(p.ClientCertificates)
	}
	builder = builder.SetNillableNameIDFormat(p.NameIDFormat)
	builder = builder.SetNillableWantAssertionSigned(p.WantAssertionSigned)
	builder = builder.SetNillableWantResponseSigned(p.WantResponseSigned)
	builder = builder.SetNillableDefaultRelayState(p.DefaultRelayState)

	// --- Common ---
	if p.AttributeMappings != nil {
		builder = builder.SetAttributeMappings(p.AttributeMappings)
	}
	builder = builder.SetNillableRequireConsent(p.RequireConsent)
	builder = builder.SetNillableMetadataURL(p.MetadataURL)

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainClientApp(e), nil
}

func (r *entClientAppRepository) Delete(ctx context.Context, id string) error {
	_, err := r.client.ClientApp.UpdateOneID(id).SetDeletedAt(time.Now()).Save(ctx)
	return err
}

func toDomainClientApp(e *ent.ClientApp) *domain.ClientApp {
	return &domain.ClientApp{
		ID:           e.ID,
		RealmID:      e.RealmID,
		ManagedBy:    domain.ClientAppManagedBy(e.ManagedBy),
		Name:         e.Name,
		Protocol:     domain.ClientAppProtocol(e.Protocol),
		Status:       domain.ClientAppStatus(e.Status),
		CreatedAt:    e.CreatedAt,
		UpdatedAt:    e.UpdatedAt,
		DeletedAt:    e.DeletedAt,
		OwnerAdminID: e.OwnerAdminID,

		ClientID:                e.ClientID,
		ClientSecretHash:        e.ClientSecretHash,
		ClientType:              domain.ClientAppType(e.ClientType),
		RedirectURIs:            e.RedirectUris,
		PostLogoutRedirectURIs:  e.PostLogoutRedirectUris,
		AllowedGrantTypes:       e.AllowedGrantTypes,
		AllowedScopes:           e.AllowedScopes,
		TokenEndpointAuthMethod: e.TokenEndpointAuthMethod,
		IDTokenSignedAlg:        e.IDTokenSignedAlg,
		AccessTokenTTL:          e.AccessTokenTTL,
		RefreshTokenTTL:         e.RefreshTokenTTL,
		IDTokenTTL:              e.IDTokenTTL,
		RequirePKCE:             e.RequirePkce,

		EntityID:            e.EntityID,
		ACSURL:              e.AcsURL,
		SLOURL:              e.SloURL,
		ClientCertificates:  e.ClientCertificates,
		NameIDFormat:        e.NameIDFormat,
		WantAssertionSigned: e.WantAssertionSigned,
		WantResponseSigned:  e.WantResponseSigned,
		DefaultRelayState:   e.DefaultRelayState,

		AttributeMappings: e.AttributeMappings,
		RequireConsent:    e.RequireConsent,
		MetadataURL:       e.MetadataURL,
	}
}
