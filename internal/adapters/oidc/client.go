package oidc

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

const protocolOIDC = domain.ClientAppProtocolOIDC

// Standard OIDC scopes handled natively by this adapter (no ClientScope row
// needed, see modele-donnees-final.md). "openid" is mandatory, "offline_access"
// asks for a refresh token.
const (
	scopeOpenID        = oidc.ScopeOpenID
	scopeProfile       = oidc.ScopeProfile
	scopeEmail         = oidc.ScopeEmail
	scopeOfflineAccess = oidc.ScopeOfflineAccess
)

var standardScopes = []string{scopeOpenID, scopeProfile, scopeEmail, scopeOfflineAccess}

// client exposes a core.ProtocolClient to the library (op.Client).
type client struct {
	pc       *core.ProtocolClient
	loginURL string // ".../oidc/login?id=" (the request id is appended)
}

var _ op.Client = (*client)(nil)

func (c *client) GetID() string                    { return c.pc.App.ClientID }
func (c *client) RedirectURIs() []string           { return c.pc.App.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return c.pc.App.PostLogoutRedirectURIs }

// ApplicationType drives the library's redirect URI rules:
//   - Web (confidential): exact https URIs (http only on localhost, checked
//     when the client is created);
//   - Native (public, loopback or custom scheme URIs): RFC 8252, any port on
//     the loopback interface;
//   - UserAgent (public SPA on https).
func (c *client) ApplicationType() op.ApplicationType {
	if !isPublic(c.pc.App) {
		return op.ApplicationTypeWeb
	}
	for _, u := range c.pc.App.RedirectURIs {
		if !strings.HasPrefix(u, "https://") {
			return op.ApplicationTypeNative
		}
	}
	return op.ApplicationTypeUserAgent
}

func (c *client) AuthMethod() oidc.AuthMethod {
	switch {
	case isPublic(c.pc.App):
		return oidc.AuthMethodNone
	case c.pc.App.TokenEndpointAuthMethod == "client_secret_post":
		return oidc.AuthMethodPost
	default:
		return oidc.AuthMethodBasic
	}
}

func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	allowed := c.pc.App.AllowedGrantTypes
	if len(allowed) == 0 {
		return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
	}
	out := make([]oidc.GrantType, 0, 2)
	for _, g := range []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken} {
		if slices.Contains(allowed, string(g)) {
			out = append(out, g)
		}
	}
	return out
}

func (c *client) LoginURL(id string) string { return c.loginURL + url.QueryEscape(id) }

func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

func (c *client) IDTokenLifetime() time.Duration {
	if c.pc.App.IDTokenTTL > 0 {
		return time.Duration(c.pc.App.IDTokenTTL) * time.Second
	}
	return time.Hour
}

// DevMode would relax the library's redirect URI checks: never.
func (c *client) DevMode() bool { return false }

func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// IsScopeAllowed is asked for every non-standard scope of a request.
func (c *client) IsScopeAllowed(scope string) bool { return allowsScope(c.pc, scope) }

// IDTokenUserinfoClaimsAssertion: put the profile/email claims in the
// id_token too, not only at /userinfo. Most applications expect them there
// (Keycloak does the same).
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }

func (c *client) ClockSkew() time.Duration { return 0 }

func isPublic(app *domain.ClientApp) bool { return app.ClientType == domain.ClientAppTypePublic }

func hasGrant(pc *core.ProtocolClient, g oidc.GrantType) bool {
	return slices.Contains((&client{pc: pc}).GrantTypes(), g)
}

// allowsScope: may this client ask for this scope? Standard scopes need to
// be in allowed_scopes (all of them when the list is empty); custom scopes
// need a ClientScopeMapping. offline_access also needs the refresh grant.
func allowsScope(pc *core.ProtocolClient, scope string) bool {
	if scope == scopeOpenID {
		return true
	}
	if slices.Contains(standardScopes, scope) {
		if scope == scopeOfflineAccess && !hasGrant(pc, oidc.GrantTypeRefreshToken) {
			return false
		}
		return len(pc.App.AllowedScopes) == 0 || slices.Contains(pc.App.AllowedScopes, scope)
	}
	for _, cs := range pc.Scopes {
		if cs.Name == scope && cs.Protocol != domain.ClientScopeProtocolSAML2 {
			return true
		}
	}
	return false
}
