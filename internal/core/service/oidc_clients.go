package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


var ErrInvalidClientConfig = errors.New("service: invalid client configuration")

const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

// Client authentication methods at the token endpoint (RFC 7591 names).
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"
)

// StandardOIDCScopes are handled natively by the OIDC adapter (no
// ClientScope row needed). offline_access asks for a refresh token.
var StandardOIDCScopes = []string{"openid", "profile", "email", "offline_access"}

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

// OIDCClientInput is what an admin provides to create an OIDC client.
type OIDCClientInput struct {
	RealmID  string
	Name     string
	ClientID string
	// Public: an app that cannot keep a secret (SPA, mobile, CLI). It has
	// no secret and must use PKCE.
	Public                 bool
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// Scopes the client may request: standard ones and names of existing
	// ClientScopes of the realm. "openid" is always added.
	Scopes []string
	// GrantTypes: empty means authorization_code + refresh_token.
	GrantTypes []string
	// TokenEndpointAuthMethod for confidential clients: client_secret_basic
	// (default) or client_secret_post.
	TokenEndpointAuthMethod string
	// DisablePKCE turns PKCE off for a confidential client. Refused for a
	// public client.
	DisablePKCE bool
	AllowRoles  []string
	AllowGroups []string
	// Secret supplied from outside (config-as-code). Empty: generated.
	Secret    string
	GrantedBy string // written on ClientRole/ClientGroup rows ("cli:alice")
	RequireConsent bool
}

// OIDCClientService creates and maintains OIDC clients.
type OIDCClientService struct {
	clients repository.ClientRepository
	scopes  repository.ClientScopeRepository
	roles   repository.RoleRepository
	groups  repository.GroupRepository
}

func NewOIDCClientService(clients repository.ClientRepository, scopes repository.ClientScopeRepository,
	roles repository.RoleRepository, groups repository.GroupRepository) *OIDCClientService {
	return &OIDCClientService{clients: clients, scopes: scopes, roles: roles, groups: groups}
}

// Create validates the input, creates the client and its grants, and returns
// the secret (empty for a public client). The secret is shown once: only its
// hash is stored.
func (s *OIDCClientService) Create(ctx context.Context, in OIDCClientInput) (*domain.ClientApp, string, error) {
	cfg, err := NormalizeOIDCClient(in)
	if err != nil {
		return nil, "", err
	}
	if _, err := s.clients.GetByRealmAndClientID(ctx, in.RealmID, cfg.ClientID); err == nil {
		return nil, "", fmt.Errorf("%w: client_id %q already exists in this realm", ErrInvalidClientConfig, cfg.ClientID)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, "", err
	}

	// Resolve every name BEFORE writing anything: a typo must not leave a
	// half-created client behind.
	custom, err := s.resolveScopes(ctx, in.RealmID, cfg.CustomScopes)
	if err != nil {
		return nil, "", err
	}
	roleIDs, err := s.resolveRoles(ctx, in.RealmID, in.AllowRoles)
	if err != nil {
		return nil, "", err
	}
	groupIDs, err := s.resolveGroups(ctx, in.RealmID, in.AllowGroups)
	if err != nil {
		return nil, "", err
	}

	secret, hash := "", ""
	if !in.Public {
		if in.Secret != "" {
			secret, hash = in.Secret, HashClientSecret(in.Secret)
		} else {
			secret, hash = NewClientSecret()
		}
	}

	app, err := s.clients.Create(ctx, repository.CreateClientAppParams{
		RealmID:  in.RealmID,
		Name:     cfg.Name,
		Protocol: domain.ClientAppProtocolOIDC,
	})
	if err != nil {
		return nil, "", fmt.Errorf("create client: %w", err)
	}
	clientType := domain.ClientAppTypeConfidential
	if in.Public {
		clientType = domain.ClientAppTypePublic
	}
	requirePKCE := !in.DisablePKCE
	upd := repository.UpdateClientAppParams{
		ClientID:                &cfg.ClientID,
		ClientType:              &clientType,
		RedirectURIs:            cfg.RedirectURIs,
		PostLogoutRedirectURIs:  cfg.PostLogoutRedirectURIs,
		AllowedGrantTypes:       cfg.GrantTypes,
		AllowedScopes:           cfg.AllowedScopes,
		TokenEndpointAuthMethod: &cfg.AuthMethod,
		RequirePKCE:             &requirePKCE,
		RequireConsent:          &in.RequireConsent,
	}
	if hash != "" {
		upd.ClientSecretHash = &hash
	}
	if app, err = s.clients.Update(ctx, app.ID, upd); err != nil {
		return nil, "", fmt.Errorf("configure client: %w", err)
	}

	for _, id := range custom {
		if err := s.clients.MapScope(ctx, app.ID, id); err != nil {
			return nil, "", fmt.Errorf("map scope: %w", err)
		}
	}
	for _, id := range roleIDs {
		if err := s.clients.GrantRole(ctx, app.ID, id, in.GrantedBy); err != nil {
			return nil, "", fmt.Errorf("grant role: %w", err)
		}
	}
	for _, id := range groupIDs {
		if err := s.clients.GrantGroup(ctx, app.ID, id, in.GrantedBy); err != nil {
			return nil, "", fmt.Errorf("grant group: %w", err)
		}
	}
	return app, secret, nil
}

// RotateSecret replaces the secret of a confidential client. The old one
// stops working at once: deploy the new one to the application first.
func (s *OIDCClientService) RotateSecret(ctx context.Context, realmID, clientID string) (string, error) {
	app, err := s.clients.GetByRealmAndClientID(ctx, realmID, clientID)
	if errors.Is(err, repository.ErrNotFound) {
		return "", fmt.Errorf("%w: unknown client_id %q", ErrInvalidClientConfig, clientID)
	}
	if err != nil {
		return "", err
	}
	if app.ClientType == domain.ClientAppTypePublic {
		return "", fmt.Errorf("%w: %q is a public client, it has no secret", ErrInvalidClientConfig, clientID)
	}
	secret, hash := NewClientSecret()
	if _, err := s.clients.Update(ctx, app.ID, repository.UpdateClientAppParams{ClientSecretHash: &hash}); err != nil {
		return "", err
	}
	return secret, nil
}

// List returns the OIDC clients of a realm (deleted ones excluded).
func (s *OIDCClientService) List(ctx context.Context, realmID string) ([]*domain.ClientApp, error) {
	all, err := s.clients.ListByRealm(ctx, realmID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ClientApp, 0, len(all))
	for _, c := range all {
		if c.Protocol == domain.ClientAppProtocolOIDC && !c.IsDeleted() {
			out = append(out, c)
		}
	}
	return out, nil
}

// NormalizedOIDCClient is the validated form of OIDCClientInput.
type NormalizedOIDCClient struct {
	Name                   string
	ClientID               string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	AllowedScopes          []string // every allowed scope name, standard + custom
	CustomScopes           []string // the ones that need a ClientScope row
	AuthMethod             string
}

// NormalizeOIDCClient checks an input without touching the database.
func NormalizeOIDCClient(in OIDCClientInput) (*NormalizedOIDCClient, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidClientConfig, fmt.Sprintf(format, a...))
	}
	out := &NormalizedOIDCClient{Name: strings.TrimSpace(in.Name), ClientID: strings.TrimSpace(in.ClientID)}
	if !clientIDPattern.MatchString(out.ClientID) {
		return nil, bad("client_id must be 1-128 characters among A-Z a-z 0-9 . _ ~ -")
	}
	if out.Name == "" {
		out.Name = out.ClientID
	}

	if len(in.RedirectURIs) == 0 {
		return nil, bad("at least one redirect URI is required")
	}
	for _, u := range in.RedirectURIs {
		if err := validateRedirectURI(u, in.Public); err != nil {
			return nil, bad("redirect URI %q: %v", u, err)
		}
		out.RedirectURIs = appendUnique(out.RedirectURIs, u)
	}
	for _, u := range in.PostLogoutRedirectURIs {
		if err := validateRedirectURI(u, in.Public); err != nil {
			return nil, bad("post-logout redirect URI %q: %v", u, err)
		}
		out.PostLogoutRedirectURIs = appendUnique(out.PostLogoutRedirectURIs, u)
	}
	if out.PostLogoutRedirectURIs == nil {
		out.PostLogoutRedirectURIs = []string{}
	}

	grants := in.GrantTypes
	if len(grants) == 0 {
		grants = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	for _, g := range grants {
		if g != GrantAuthorizationCode && g != GrantRefreshToken {
			return nil, bad("grant type %q is not supported (only authorization_code and refresh_token)", g)
		}
		out.GrantTypes = appendUnique(out.GrantTypes, g)
	}
	if !slices.Contains(out.GrantTypes, GrantAuthorizationCode) {
		return nil, bad("the authorization_code grant is required")
	}

	out.AllowedScopes = []string{"openid"}
	for _, sc := range in.Scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		if strings.ContainsAny(sc, " \"\\") {
			return nil, bad("scope %q contains a forbidden character", sc)
		}
		out.AllowedScopes = appendUnique(out.AllowedScopes, sc)
		if !slices.Contains(StandardOIDCScopes, sc) {
			out.CustomScopes = appendUnique(out.CustomScopes, sc)
		}
	}
	if slices.Contains(out.AllowedScopes, "offline_access") && !slices.Contains(out.GrantTypes, GrantRefreshToken) {
		return nil, bad("offline_access needs the refresh_token grant")
	}

	switch {
	case in.Public:
		if in.DisablePKCE {
			return nil, bad("PKCE cannot be disabled for a public client")
		}
		if in.Secret != "" {
			return nil, bad("a public client has no secret")
		}
		if in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != AuthMethodNone {
			return nil, bad("a public client authenticates with %q only", AuthMethodNone)
		}
		out.AuthMethod = AuthMethodNone
	default:
		switch in.TokenEndpointAuthMethod {
		case "", AuthMethodClientSecretBasic:
			out.AuthMethod = AuthMethodClientSecretBasic
		case AuthMethodClientSecretPost:
			out.AuthMethod = AuthMethodClientSecretPost
		default:
			return nil, bad("token endpoint auth method %q is not supported", in.TokenEndpointAuthMethod)
		}
		if in.Secret != "" && len(in.Secret) < MinClientSecretLength {
			return nil, bad("a supplied secret needs at least %d characters", MinClientSecretLength)
		}
	}
	return out, nil
}

// validateRedirectURI applies OAuth 2.0 Security BCP (RFC 9700, section 4.1)
// and RFC 8252 (native apps): exact absolute URIs, no fragment, no wildcard,
// https, or http on the loopback interface only. Custom schemes
// ("com.example.app:/cb") are for native, i.e. public, apps.
func validateRedirectURI(raw string, public bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if !u.IsAbs() {
		return errors.New("must be absolute")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not contain a fragment")
	}
	if strings.Contains(raw, "*") {
		return errors.New("wildcards are not allowed")
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return errors.New("missing host")
		}
		return nil
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return errors.New("http is only allowed for localhost / loopback addresses")
		}
		return nil
	case "javascript", "data", "file", "vbscript":
		return fmt.Errorf("scheme %q is not allowed", u.Scheme)
	default:
		if !public {
			return errors.New("custom schemes are for public (native) clients")
		}
		if !strings.Contains(u.Scheme, ".") {
			return errors.New("a custom scheme must be a reverse domain name, e.g. com.example.app (RFC 8252, section 7.1)")
		}
		return nil
	}
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func appendUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func (s *OIDCClientService) resolveScopes(ctx context.Context, realmID string, names []string) ([]string, error) {
	ids := make([]string, 0, len(names))
	for _, n := range names {
		cs, err := s.scopes.GetByRealmAndName(ctx, realmID, n)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: unknown client scope %q (create it first, or use a standard scope: %s)",
				ErrInvalidClientConfig, n, strings.Join(StandardOIDCScopes, ", "))
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, cs.ID)
	}
	return ids, nil
}

func (s *OIDCClientService) resolveRoles(ctx context.Context, realmID string, names []string) ([]string, error) {
	ids := make([]string, 0, len(names))
	for _, n := range names {
		r, err := s.roles.GetByRealmAndName(ctx, realmID, n)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: unknown role %q", ErrInvalidClientConfig, n)
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, r.ID)
	}
	return ids, nil
}

func (s *OIDCClientService) resolveGroups(ctx context.Context, realmID string, names []string) ([]string, error) {
	ids := make([]string, 0, len(names))
	for _, n := range names {
		g, err := s.groups.GetByRealmAndName(ctx, realmID, n)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: unknown group %q", ErrInvalidClientConfig, n)
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, g.ID)
	}
	return ids, nil
}
