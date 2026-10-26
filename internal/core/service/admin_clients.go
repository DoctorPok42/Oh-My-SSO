package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


type ClientSummary struct {
	ID        string                   `json:"id"`
	Name      string                   `json:"name"`
	Protocol  domain.ClientAppProtocol `json:"protocol"`
	Status    domain.ClientAppStatus   `json:"status"`
	ManagedBy string                   `json:"managed_by"`
	ClientID  string                   `json:"client_id,omitempty"`
	EntityID  string                   `json:"entity_id,omitempty"`
	CreatedAt time.Time                `json:"created_at"`
}

// ClientScopeChoice: a client scope mapped to a client.
type ClientScopeChoice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Required bool   `json:"required"`
}

// CertificateView: a SAML certificate of a service provider.
type CertificateView struct {
	Fingerprint string     `json:"fingerprint"` // SHA-256, hex
	Subject     string     `json:"subject"`
	NotBefore   *time.Time `json:"not_before"` // admin window
	NotAfter    *time.Time `json:"not_after"`
	ExpiresAt   time.Time  `json:"expires_at"` // X.509 NotAfter
	Status      string     `json:"status"`     // active | pending | expired
}

// ClientView: the client drawer. The secret is never part of it.
type ClientView struct {
	ClientSummary
	RequireConsent bool                   `json:"require_consent"`
	SubjectType    string                 `json:"subject_type"`
	MFAPolicy      string                 `json:"mfa_policy"`
	MFAMethods     []string               `json:"mfa_methods"`
	ClientScopes   []ClientScopeChoice    `json:"client_scopes"`
	AllowedRoles   []NameRef              `json:"allowed_roles"`
	AllowedGroups  []NameRef              `json:"allowed_groups"`
	OIDC           *ClientOIDCView        `json:"oidc,omitempty"`
	SAML           *ClientSAMLView        `json:"saml,omitempty"`
	Mappings       map[string]interface{} `json:"attribute_mappings"`
}

type ClientOIDCView struct {
	ClientType              string   `json:"client_type"` // confidential | public
	HasSecret               bool     `json:"has_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	StandardScopes          []string `json:"standard_scopes"` // openid, profile, email, offline_access
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RequirePKCE             bool     `json:"require_pkce"`
	AccessTokenTTL          int      `json:"access_token_ttl"` // seconds, 0 = default
	RefreshTokenTTL         int      `json:"refresh_token_ttl"`
	IDTokenTTL              int      `json:"id_token_ttl"`
}

type ClientSAMLView struct {
	EntityID            string            `json:"entity_id"`
	ACSURL              string            `json:"acs_url"`
	SLOURL              string            `json:"slo_url"`
	NameIDFormat        string            `json:"name_id_format"`
	WantAssertionSigned bool              `json:"want_assertion_signed"`
	WantResponseSigned  bool              `json:"want_response_signed"`
	DefaultRelayState   string            `json:"default_relay_state"`
	Certificates        []CertificateView `json:"certificates"`
}

// ScopeChoiceInput: a client scope to map, by id.
type ScopeChoiceInput struct {
	ID       string
	Required bool
}

// ClientInput creates or changes a client. nil: unchanged (update) or
// default (create). Fields marked "create" are ignored on update.
type ClientInput struct {
	Protocol domain.ClientAppProtocol // create
	Name     *string
	Active   *bool

	// --- OIDC ---
	ClientID                *string // create; empty: generated from the name
	Public                  *bool   // create
	RedirectURIs            *[]string
	PostLogoutRedirectURIs  *[]string
	StandardScopes          *[]string
	TokenEndpointAuthMethod *string
	RequirePKCE             *bool
	AccessTokenTTL          *int
	RefreshTokenTTL         *int
	IDTokenTTL              *int

	// --- SAML ---
	EntityID           *string
	ACSURL             *string
	SLOURL             *string
	NameIDFormat       *string
	WantResponseSigned *bool
	DefaultRelayState  *string
	Pairwise           *bool                      // create
	Certificates       []domain.ClientCertificate // create

	// --- common ---
	ClientScopes    *[]ScopeChoiceInput
	AllowedRoleIDs  *[]string
	AllowedGroupIDs *[]string
	RequireConsent  *bool
	MFAPolicy       *string
	MFAMethods      *[]string
}

// ClientCreated: the new client, and its secret (shown once).
type ClientCreated struct {
	Client ClientView `json:"client"`
	Secret string     `json:"secret,omitempty"`
}

func (s *AdminService) ListClients(ctx context.Context, realm *domain.Realm, protocol domain.ClientAppProtocol) ([]ClientSummary, error) {
	all, err := s.d.Clients.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]ClientSummary, 0, len(all))
	for _, c := range all {
		if c.IsDeleted() || (protocol != "" && c.Protocol != protocol) {
			continue
		}
		out = append(out, clientSummary(c))
	}
	slices.SortFunc(out, func(a, b ClientSummary) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

func clientSummary(c *domain.ClientApp) ClientSummary {
	return ClientSummary{ID: c.ID, Name: c.Name, Protocol: c.Protocol, Status: c.Status, ManagedBy: string(c.ManagedBy),
		ClientID: c.ClientID, EntityID: c.EntityID, CreatedAt: c.CreatedAt}
}

func (s *AdminService) GetClient(ctx context.Context, realm *domain.Realm, id string) (ClientView, error) {
	c, err := s.clientInRealm(ctx, realm.ID, id)
	if err != nil {
		return ClientView{}, err
	}
	return s.clientView(ctx, c)
}

func (s *AdminService) clientView(ctx context.Context, c *domain.ClientApp) (ClientView, error) {
	grants, err := s.d.Admin.ClientGrants(ctx, c.ID)
	if err != nil {
		return ClientView{}, err
	}
	v := ClientView{
		ClientSummary:  clientSummary(c),
		RequireConsent: c.RequireConsent,
		SubjectType:    string(c.SubjectType),
		MFAPolicy:      string(c.MFAPolicy),
		MFAMethods:     methodNames(c.MFAAllowedMethods),
		ClientScopes:   []ClientScopeChoice{},
		AllowedRoles:   namedRefs(grants.RoleIDs, grants.Names),
		AllowedGroups:  namedRefs(grants.GroupIDs, grants.Names),
		Mappings:       c.AttributeMappings,
	}
	if v.MFAPolicy == "" {
		v.MFAPolicy = string(domain.ClientAppMFAInherit)
	}
	if v.SubjectType == "" {
		v.SubjectType = string(domain.ClientAppSubjectPublic)
	}
	if v.Mappings == nil {
		v.Mappings = map[string]interface{}{}
	}
	for _, m := range grants.Scopes {
		if m.Name != "" { // loaded with the mapping
			v.ClientScopes = append(v.ClientScopes, ClientScopeChoice{ID: m.ClientScopeID, Name: m.Name, Protocol: m.Protocol, Required: m.Required})
		}
	}
	slices.SortFunc(v.ClientScopes, func(a, b ClientScopeChoice) int { return strings.Compare(a.Name, b.Name) })

	switch c.Protocol {
	case domain.ClientAppProtocolOIDC:
		std := []string{}
		for _, sc := range c.AllowedScopes {
			if slices.Contains(StandardOIDCScopes, sc) {
				std = append(std, sc)
			}
		}
		v.OIDC = &ClientOIDCView{
			ClientType: string(c.ClientType), HasSecret: c.ClientSecretHash != "",
			RedirectURIs: orEmpty(c.RedirectURIs), PostLogoutRedirectURIs: orEmpty(c.PostLogoutRedirectURIs),
			StandardScopes: std, GrantTypes: orEmpty(c.AllowedGrantTypes),
			TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, RequirePKCE: c.RequirePKCE,
			AccessTokenTTL: c.AccessTokenTTL, RefreshTokenTTL: c.RefreshTokenTTL, IDTokenTTL: c.IDTokenTTL,
		}
	case domain.ClientAppProtocolSAML2:
		v.SAML = &ClientSAMLView{EntityID: c.EntityID, ACSURL: c.ACSURL, SLOURL: c.SLOURL, NameIDFormat: c.NameIDFormat,
			WantAssertionSigned: c.WantAssertionSigned, WantResponseSigned: c.WantResponseSigned,
			DefaultRelayState: c.DefaultRelayState, Certificates: s.certificateViews(c)}
	}
	return v, nil
}

func (s *AdminService) certificateViews(c *domain.ClientApp) []CertificateView {
	out := []CertificateView{}
	certs, err := c.Certificates()
	if err != nil {
		return out
	}
	now := s.d.Now()
	for _, cc := range certs {
		x, err := ParseCertificate(cc.PEM)
		if err != nil {
			continue
		}
		fp, _ := CertificateFingerprint(cc.PEM)
		v := CertificateView{Fingerprint: fp, Subject: x.Subject.String(), ExpiresAt: x.NotAfter}
		if !cc.NotBefore.IsZero() {
			t := cc.NotBefore
			v.NotBefore = &t
		}
		if !cc.NotAfter.IsZero() {
			t := cc.NotAfter
			v.NotAfter = &t
		}
		switch {
		case !now.Before(x.NotAfter) || (!cc.NotAfter.IsZero() && !now.Before(cc.NotAfter)):
			v.Status = "expired"
		case now.Before(x.NotBefore) || (!cc.NotBefore.IsZero() && now.Before(cc.NotBefore)):
			v.Status = "pending"
		default:
			v.Status = "active"
		}
		out = append(out, v)
	}
	return out
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// clientScopes checks scope choices (realm, protocol) and returns the
// mappings and the scope names.
func (s *AdminService) clientScopes(ctx context.Context, realmID string, protocol domain.ClientAppProtocol, in []ScopeChoiceInput) ([]repository.ScopeMapping, []string, error) {
	maps := []repository.ScopeMapping{}
	names := []string{}
	for _, ch := range in {
		cs, err := s.scopeInRealm(ctx, realmID, strings.TrimSpace(ch.ID))
		if err != nil {
			return nil, nil, adminInvalid("client_scopes", "unknown client scope id %q", ch.ID)
		}
		ok := cs.Protocol == domain.ClientScopeProtocolBoth ||
			(protocol == domain.ClientAppProtocolOIDC && cs.Protocol == domain.ClientScopeProtocolOIDC) ||
			(protocol == domain.ClientAppProtocolSAML2 && cs.Protocol == domain.ClientScopeProtocolSAML2)
		if !ok {
			return nil, nil, adminInvalid("client_scopes", "client scope %q is for protocol %q", cs.Name, cs.Protocol)
		}
		if slices.Contains(names, cs.Name) {
			continue
		}
		maps = append(maps, repository.ScopeMapping{ClientScopeID: cs.ID, Required: ch.Required})
		names = append(names, cs.Name)
	}
	return maps, names, nil
}

var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

// generatedClientID: "confluence-cloud-8a2f1c94" for "Confluence Cloud".
func generatedClientID(name string) string {
	slug := strings.Trim(slugPattern.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	if slug == "" {
		slug = "client"
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return slug + "-" + hex.EncodeToString(b)
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func listOr(p *[]string, def []string) []string {
	if p == nil {
		return def
	}
	return *p
}

func checkTTL(field string, v *int) error {
	if v != nil && (*v < 0 || *v > 365*24*3600) {
		return adminInvalid(field, "%s: seconds between 0 (default) and one year", field)
	}
	return nil
}

func mfaInput(policy *string, methods *[]string) (domain.ClientAppMFAPolicy, []domain.MfaMethodType) {
	p := domain.ClientAppMFAInherit
	if policy != nil && *policy != "" {
		p = domain.ClientAppMFAPolicy(*policy)
	}
	var ms []domain.MfaMethodType
	if methods != nil {
		ms = []domain.MfaMethodType{}
		for _, m := range *methods {
			ms = append(ms, domain.MfaMethodType(m))
		}
	}
	return p, ms
}

// CreateClient creates an OIDC or a SAML client from the drawer.
func (s *AdminService) CreateClient(ctx context.Context, actor AdminActor, realm *domain.Realm, in ClientInput) (*ClientCreated, error) {
	if in.Protocol != domain.ClientAppProtocolOIDC && in.Protocol != domain.ClientAppProtocolSAML2 {
		return nil, adminInvalid("protocol", "protocol must be oidc or saml2")
	}
	roles, err := s.checkRoleIDs(ctx, realm.ID, listOr(in.AllowedRoleIDs, nil))
	if err != nil {
		return nil, err
	}
	groups, err := s.checkGroupIDs(ctx, realm.ID, listOr(in.AllowedGroupIDs, nil))
	if err != nil {
		return nil, err
	}
	var choices []ScopeChoiceInput
	if in.ClientScopes != nil {
		choices = *in.ClientScopes
	}
	scopeMaps, scopeNames, err := s.clientScopes(ctx, realm.ID, in.Protocol, choices)
	if err != nil {
		return nil, err
	}
	for field, v := range map[string]*int{"access_token_ttl": in.AccessTokenTTL, "refresh_token_ttl": in.RefreshTokenTTL, "id_token_ttl": in.IDTokenTTL} {
		if err := checkTTL(field, v); err != nil {
			return nil, err
		}
	}
	name := strOr(in.Name, "")

	var app *domain.ClientApp
	var secret string
	switch in.Protocol {
	case domain.ClientAppProtocolOIDC:
		clientID := strOr(in.ClientID, "")
		if clientID == "" {
			if name == "" {
				return nil, adminInvalid("name", "a name or a client_id is required")
			}
			clientID = generatedClientID(name)
		}
		app, secret, err = s.d.OIDCClients.Create(ctx, OIDCClientInput{
			RealmID: realm.ID, Name: name, ClientID: clientID, Public: boolOr(in.Public, false),
			RedirectURIs: listOr(in.RedirectURIs, nil), PostLogoutRedirectURIs: listOr(in.PostLogoutRedirectURIs, nil),
			Scopes:                  append(slices.Clone(listOr(in.StandardScopes, nil)), scopeNames...),
			TokenEndpointAuthMethod: strOr(in.TokenEndpointAuthMethod, ""),
			DisablePKCE:             !boolOr(in.RequirePKCE, true),
			RequireConsent:          boolOr(in.RequireConsent, false),
			GrantedBy:               actor.By(),
		})
	case domain.ClientAppProtocolSAML2:
		app, err = s.d.SAMLClients.Create(ctx, SAMLClientInput{
			RealmID: realm.ID, Name: name, EntityID: strOr(in.EntityID, ""), ACSURL: strOr(in.ACSURL, ""),
			SLOURL: strOr(in.SLOURL, ""), NameIDFormat: strOr(in.NameIDFormat, ""), Certificates: in.Certificates,
			WantResponseSigned: boolOr(in.WantResponseSigned, false), Pairwise: boolOr(in.Pairwise, false),
			Scopes: scopeNames, RequireConsent: boolOr(in.RequireConsent, false), GrantedBy: actor.By(),
		})
	}
	if err != nil {
		return nil, asAdminError(err)
	}

	// Grants by id (the services above resolve names; the console has ids).
	if err := s.d.Admin.SetClientRoles(ctx, app.ID, roles, actor.By()); err != nil {
		return nil, err
	}
	if err := s.d.Admin.SetClientGroups(ctx, app.ID, groups, actor.By()); err != nil {
		return nil, err
	}
	if err := s.d.Admin.SetClientScopes(ctx, app.ID, scopeMaps); err != nil {
		return nil, err
	}
	upd := repository.UpdateClientAppParams{AccessTokenTTL: in.AccessTokenTTL, RefreshTokenTTL: in.RefreshTokenTTL, IDTokenTTL: in.IDTokenTTL}
	if in.DefaultRelayState != nil {
		upd.DefaultRelayState = in.DefaultRelayState
	}
	if in.Active != nil && !*in.Active {
		st := domain.ClientAppInactive
		upd.Status = &st
	}
	if app, err = s.d.Clients.Update(ctx, app.ID, upd); err != nil {
		return nil, err
	}
	if in.MFAPolicy != nil || in.MFAMethods != nil {
		policy, methods := mfaInput(in.MFAPolicy, in.MFAMethods)
		if app, err = s.d.MFAPolicy.SetClientPolicy(ctx, SetClientMFAPolicyInput{RealmID: realm.ID, ClientRef: app.ID,
			Policy: policy, AllowedMethods: methods, Actor: PolicyActor{TriggeredBy: actor.By()}}); err != nil {
			return nil, asAdminError(err)
		}
	}

	s.auditAdmin(ctx, actor, realm.ID, "client.create", "ClientApp", app.ID, domain.AuditLogInfo, map[string]interface{}{
		"name": app.Name, "protocol": string(app.Protocol), "client_id": app.ClientID, "entity_id": app.EntityID,
		"role_ids": roles, "group_ids": groups,
	})
	view, err := s.clientView(ctx, app)
	if err != nil {
		return nil, err
	}
	return &ClientCreated{Client: view, Secret: secret}, nil
}

// UpdateClient applies the drawer's changes. The protocol rules are
// re-checked on the merged result, exactly as for a new client.
func (s *AdminService) UpdateClient(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, in ClientInput) (ClientView, error) {
	app, err := s.clientInRealm(ctx, realm.ID, id)
	if err != nil {
		return ClientView{}, err
	}
	if app.ManagedBy == domain.ClientAppManagedByConfig {
		return ClientView{}, errManagedByConfig
	}
	for field, v := range map[string]*int{"access_token_ttl": in.AccessTokenTTL, "refresh_token_ttl": in.RefreshTokenTTL, "id_token_ttl": in.IDTokenTTL} {
		if err := checkTTL(field, v); err != nil {
			return ClientView{}, err
		}
	}
	grants, err := s.d.Admin.ClientGrants(ctx, app.ID)
	if err != nil {
		return ClientView{}, err
	}

	// Client scopes: the new choice, or the current mappings.
	var scopeMaps []repository.ScopeMapping
	var scopeNames []string
	if in.ClientScopes != nil {
		if scopeMaps, scopeNames, err = s.clientScopes(ctx, realm.ID, app.Protocol, *in.ClientScopes); err != nil {
			return ClientView{}, err
		}
	} else {
		for _, m := range grants.Scopes {
			if cs, err := s.d.Scopes.GetByID(ctx, m.ClientScopeID); err == nil {
				scopeNames = append(scopeNames, cs.Name)
			}
		}
	}
	var roles, groups []string
	if in.AllowedRoleIDs != nil {
		if roles, err = s.checkRoleIDs(ctx, realm.ID, *in.AllowedRoleIDs); err != nil {
			return ClientView{}, err
		}
	}
	if in.AllowedGroupIDs != nil {
		if groups, err = s.checkGroupIDs(ctx, realm.ID, *in.AllowedGroupIDs); err != nil {
			return ClientView{}, err
		}
	}

	upd := repository.UpdateClientAppParams{
		RequireConsent: in.RequireConsent, AccessTokenTTL: in.AccessTokenTTL,
		RefreshTokenTTL: in.RefreshTokenTTL, IDTokenTTL: in.IDTokenTTL,
	}
	changed := []string{}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" {
			return ClientView{}, adminInvalid("name", "name cannot be empty")
		}
		upd.Name = &n
		changed = append(changed, "name")
	}
	if in.Active != nil {
		st := domain.ClientAppInactive
		if *in.Active {
			st = domain.ClientAppActive
		}
		upd.Status = &st
		changed = append(changed, "status")
	}

	switch app.Protocol {
	case domain.ClientAppProtocolOIDC:
		std := []string{}
		for _, sc := range app.AllowedScopes {
			if slices.Contains(StandardOIDCScopes, sc) {
				std = append(std, sc)
			}
		}
		requirePKCE := boolOr(in.RequirePKCE, app.RequirePKCE)
		norm, err := NormalizeOIDCClient(OIDCClientInput{
			Name: strOr(upd.Name, app.Name), ClientID: app.ClientID, Public: app.ClientType == domain.ClientAppTypePublic,
			RedirectURIs:            listOr(in.RedirectURIs, app.RedirectURIs),
			PostLogoutRedirectURIs:  listOr(in.PostLogoutRedirectURIs, app.PostLogoutRedirectURIs),
			Scopes:                  append(slices.Clone(listOr(in.StandardScopes, std)), scopeNames...),
			GrantTypes:              app.AllowedGrantTypes,
			TokenEndpointAuthMethod: strOr(in.TokenEndpointAuthMethod, app.TokenEndpointAuthMethod),
			DisablePKCE:             !requirePKCE,
		})
		if err != nil {
			return ClientView{}, asAdminError(err)
		}
		upd.RedirectURIs = norm.RedirectURIs
		upd.PostLogoutRedirectURIs = norm.PostLogoutRedirectURIs
		upd.AllowedScopes = norm.AllowedScopes
		upd.TokenEndpointAuthMethod = &norm.AuthMethod
		upd.RequirePKCE = &requirePKCE
		for f, set := range map[string]bool{"redirect_uris": in.RedirectURIs != nil, "post_logout_redirect_uris": in.PostLogoutRedirectURIs != nil,
			"standard_scopes": in.StandardScopes != nil, "token_endpoint_auth_method": in.TokenEndpointAuthMethod != nil, "require_pkce": in.RequirePKCE != nil} {
			if set {
				changed = append(changed, f)
			}
		}

	case domain.ClientAppProtocolSAML2:
		certs, err := app.Certificates()
		if err != nil {
			return ClientView{}, adminInvalid("certificates", "stored certificates cannot be read: %v", err)
		}
		norm, err := NormalizeSAMLClient(SAMLClientInput{
			Name: strOr(upd.Name, app.Name), EntityID: strOr(in.EntityID, app.EntityID), ACSURL: strOr(in.ACSURL, app.ACSURL),
			SLOURL: strOr(in.SLOURL, app.SLOURL), NameIDFormat: strOr(in.NameIDFormat, app.NameIDFormat), Certificates: certs,
			WantResponseSigned: boolOr(in.WantResponseSigned, app.WantResponseSigned),
			Pairwise:           app.SubjectType == domain.ClientAppSubjectPairwise,
		})
		if err != nil {
			return ClientView{}, asAdminError(err)
		}
		if norm.EntityID != app.EntityID {
			if other, err := s.d.Clients.GetByRealmAndEntityID(ctx, realm.ID, norm.EntityID); err == nil && other.ID != app.ID {
				return ClientView{}, adminConflict("entity_id_taken", "entity_id %q is already used in this realm", norm.EntityID)
			}
		}
		upd.EntityID, upd.ACSURL, upd.SLOURL, upd.NameIDFormat = &norm.EntityID, &norm.ACSURL, &norm.SLOURL, &norm.NameIDFormat
		upd.WantResponseSigned = in.WantResponseSigned
		upd.DefaultRelayState = in.DefaultRelayState
		for f, set := range map[string]bool{"entity_id": in.EntityID != nil, "acs_url": in.ACSURL != nil, "slo_url": in.SLOURL != nil,
			"name_id_format": in.NameIDFormat != nil, "want_response_signed": in.WantResponseSigned != nil, "default_relay_state": in.DefaultRelayState != nil} {
			if set {
				changed = append(changed, f)
			}
		}
	}

	if _, err := s.d.Clients.Update(ctx, app.ID, upd); err != nil {
		return ClientView{}, fmt.Errorf("update client: %w", err)
	}
	if in.ClientScopes != nil {
		if err := s.d.Admin.SetClientScopes(ctx, app.ID, scopeMaps); err != nil {
			return ClientView{}, err
		}
		changed = append(changed, "client_scopes")
	}
	if in.AllowedRoleIDs != nil {
		if err := s.d.Admin.SetClientRoles(ctx, app.ID, roles, actor.By()); err != nil {
			return ClientView{}, err
		}
		changed = append(changed, "allowed_roles")
	}
	if in.AllowedGroupIDs != nil {
		if err := s.d.Admin.SetClientGroups(ctx, app.ID, groups, actor.By()); err != nil {
			return ClientView{}, err
		}
		changed = append(changed, "allowed_groups")
	}
	if in.RequireConsent != nil {
		changed = append(changed, "require_consent")
	}
	if in.MFAPolicy != nil || in.MFAMethods != nil {
		policy, methods := mfaInput(in.MFAPolicy, in.MFAMethods)
		if in.MFAPolicy == nil {
			policy = app.MFAPolicy
			if policy == "" {
				policy = domain.ClientAppMFAInherit
			}
		}
		if in.MFAMethods == nil {
			methods = app.MFAAllowedMethods
		}
		if _, err := s.d.MFAPolicy.SetClientPolicy(ctx, SetClientMFAPolicyInput{RealmID: realm.ID, ClientRef: app.ID,
			Policy: policy, AllowedMethods: methods, Actor: PolicyActor{TriggeredBy: actor.By()}}); err != nil {
			return ClientView{}, asAdminError(err)
		}
		changed = append(changed, "mfa_policy")
	}
	slices.Sort(changed)
	s.auditAdmin(ctx, actor, realm.ID, "client.update", "ClientApp", app.ID, domain.AuditLogInfo, map[string]interface{}{"changed": changed})

	app, err = s.d.Clients.GetByID(ctx, app.ID)
	if err != nil {
		return ClientView{}, err
	}
	return s.clientView(ctx, app)
}

// DeleteClient removes a client (soft delete: its id is never reused, and
// tokens it holds stop working, since the client cannot be found any more).
func (s *AdminService) DeleteClient(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) error {
	app, err := s.clientInRealm(ctx, realm.ID, id)
	if err != nil {
		return err
	}
	if app.ManagedBy == domain.ClientAppManagedByConfig {
		return errManagedByConfig
	}
	if err := s.d.Clients.Delete(ctx, app.ID); err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "client.delete", "ClientApp", app.ID, domain.AuditLogWarning, map[string]interface{}{
		"name": app.Name, "client_id": app.ClientID, "entity_id": app.EntityID,
	})
	return nil
}

// RotateClientSecret gives a confidential OIDC client a new secret, shown
// once. The old one stops working at once.
func (s *AdminService) RotateClientSecret(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) (string, error) {
	app, err := s.clientInRealm(ctx, realm.ID, id)
	if err != nil {
		return "", err
	}
	if app.ManagedBy == domain.ClientAppManagedByConfig {
		return "", errManagedByConfig
	}
	if app.Protocol != domain.ClientAppProtocolOIDC {
		return "", adminInvalid("protocol", "only OIDC clients have a secret")
	}
	secret, err := s.d.OIDCClients.RotateSecret(ctx, realm.ID, app.ClientID)
	if err != nil {
		return "", asAdminError(err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "client.secret_rotate", "ClientApp", app.ID, domain.AuditLogWarning, nil)
	return secret, nil
}

// AddClientCertificate registers a SAML certificate (rotation without
// downtime: add the new one with a window, then remove the old one).
func (s *AdminService) AddClientCertificate(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, cert domain.ClientCertificate) (ClientView, error) {
	app, err := s.samlClientForCerts(ctx, realm, id)
	if err != nil {
		return ClientView{}, err
	}
	updated, err := s.d.SAMLClients.AddCertificate(ctx, realm.ID, app.EntityID, cert)
	if err != nil {
		return ClientView{}, asAdminError(err)
	}
	fp, _ := CertificateFingerprint(cert.PEM)
	s.auditAdmin(ctx, actor, realm.ID, "client.certificate_add", "ClientApp", app.ID, domain.AuditLogWarning, map[string]interface{}{"fingerprint": fp})
	return s.clientView(ctx, updated)
}

func (s *AdminService) RemoveClientCertificate(ctx context.Context, actor AdminActor, realm *domain.Realm, id, fingerprint string) (ClientView, error) {
	app, err := s.samlClientForCerts(ctx, realm, id)
	if err != nil {
		return ClientView{}, err
	}
	updated, err := s.d.SAMLClients.RemoveCertificate(ctx, realm.ID, app.EntityID, fingerprint)
	if err != nil {
		return ClientView{}, asAdminError(err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "client.certificate_remove", "ClientApp", app.ID, domain.AuditLogWarning, map[string]interface{}{"fingerprint": fingerprint})
	return s.clientView(ctx, updated)
}

func (s *AdminService) samlClientForCerts(ctx context.Context, realm *domain.Realm, id string) (*domain.ClientApp, error) {
	app, err := s.clientInRealm(ctx, realm.ID, id)
	if err != nil {
		return nil, err
	}
	if app.ManagedBy == domain.ClientAppManagedByConfig {
		return nil, errManagedByConfig
	}
	if app.Protocol != domain.ClientAppProtocolSAML2 {
		return nil, adminInvalid("protocol", "only SAML clients have certificates")
	}
	return app, nil
}
