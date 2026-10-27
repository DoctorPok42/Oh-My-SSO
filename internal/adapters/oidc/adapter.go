package oidc

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/oidcstore"
)

// Config of the adapter. Everything comes from the server's environment.
type Config struct {
	// PublicURL is the external base URL of the IdP, e.g.
	// "https://sso.example.com". The issuer of a realm is
	// PublicURL + "/r/" + realm. It is configured, never taken from the Host
	// header: otherwise anybody could make us announce another issuer.
	PublicURL string
	// AllowInsecureHTTP accepts an http:// PublicURL. OIDC requires https
	// issuers: development on localhost only.
	AllowInsecureHTTP bool
	// SessionCookieName is the SSO session cookie (httpserver.SessionCookieName).
	SessionCookieName string
	// DeviceCookieName identifies the browser (httpserver.DeviceCookieName):
	// the accounts of "Pick an account" are remembered per device.
	DeviceCookieName string
	// PasskeysEnabled shows the passkey buttons on the login page.
	PasskeysEnabled bool
	// DevPages links to /r/{realm}/dev/mfa when a user must enroll a factor
	// first (APP_ENV=development).
	DevPages bool
	PasswordReset bool
	// Now is the clock (tests). nil: time.Now.
	Now func() time.Time
	// Logger: nil means slog.Default().
	Logger *slog.Logger
}

// Adapter is the OIDC protocol adapter. Mount Handler() on /r/{realm}/oidc/*
// and DiscoveryHandler() on /r/{realm}/.well-known/openid-configuration,
// after putting the realm in the request context (WithRealm).
type Adapter struct {
	cfg      Config
	base     string // PublicURL without trailing slash
	core     core.IdentityCore
	store    oidcstore.Store
	logger   *slog.Logger
	now      func() time.Time
	storage  *storage
	provider *op.Provider
	handler  http.Handler
	pages    *loginui.Pages
}

// Scopes and claims announced by discovery.
var (
	supportedScopes = []string{scopeOpenID, scopeProfile, scopeEmail, scopeOfflineAccess}
	supportedClaims = []string{
		"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp", "sid", "at_hash",
		"preferred_username", "name", "given_name", "family_name", "middle_name", "nickname",
		"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
		"email", "email_verified",
	}
)

// New builds the adapter.
func New(cfg Config, idp core.IdentityCore, store oidcstore.Store) (*Adapter, error) {
	base, err := checkPublicURL(cfg.PublicURL, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = "sso_session"
	}
	if cfg.DeviceCookieName == "" {
		cfg.DeviceCookieName = "sso_device"
	}
	a := &Adapter{cfg: cfg, base: base, core: idp, store: store, logger: cfg.Logger, now: cfg.Now}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.pages, err = loginui.New(a.logger); err != nil {
		return nil, err
	}
	a.storage = &storage{a: a}

	opts := []op.Option{
		// Codes are random values (see codeCrypto), not encrypted request
		// ids: no shared secret to configure and rotate across replicas.
		op.WithCrypto(codeCrypto{}),
		op.WithCustomEndpoints(
			op.NewEndpoint("oidc/authorize"),
			op.NewEndpoint("oidc/token"),
			op.NewEndpoint("oidc/userinfo"),
			op.NewEndpoint("oidc/revoke"),
			op.NewEndpoint("oidc/logout"),
			op.NewEndpoint(".well-known/jwks.json"),
		),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint("oidc/introspect")),
		// The library's default CORS policy reflects any origin WITH
		// credentials. Ours: any origin (SPAs call /token and /userinfo
		// from the browser) but never cookies, so a foreign page can only
		// use what it already holds (a code + verifier, a token).
		op.WithCORSOptions(&cors.Options{
			AllowOriginFunc:  func(string) bool { return true },
			AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodHead},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			AllowCredentials: false,
			MaxAge:           600,
		}),
	}
	if cfg.AllowInsecureHTTP {
		opts = append(opts, op.WithAllowInsecure())
	}
	a.provider, err = op.NewProvider(&op.Config{
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       supportedScopes,
		SupportedClaims:       supportedClaims,
	}, a.storage, a.issuerFromRequest, opts...)
	if err != nil {
		return nil, fmt.Errorf("oidc: provider: %w", err)
	}
	a.handler = a.routes()
	return a, nil
}

// Handler serves /r/{realm}/oidc/*. It expects to be mounted in a chi
// router under /r/{realmName} (it routes on the remaining path).
func (a *Adapter) Handler() http.Handler { return a.handler }

// DiscoveryHandler serves /r/{realm}/.well-known/openid-configuration.
func (a *Adapter) DiscoveryHandler() http.Handler {
	return a.requireRealm(http.HandlerFunc(a.handleDiscovery))
}

func (a *Adapter) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(a.requireRealm, securityHeaders)
	r.Get("/oidc/login", a.handleLogin)
	r.Post("/oidc/login/continue", a.handleContinue)
	r.Post("/oidc/consent", a.handleConsent)
	r.Get("/oidc/logged-out", a.handleLoggedOut)
	r.Get("/oidc/logout/confirm", a.handleLogoutConfirmPage)
	r.Post("/oidc/logout/confirm", a.handleLogoutConfirm)
	r.Get("/oidc/assets/{file}", handleAsset)
	r.With(a.bindBrowser).Handle("/oidc/authorize", a.provider)
	// RP-initiated logout: the library validates the request, then calls
	// storage.TerminateSessionFromRequest, which needs the browser (its
	// session cookie, a binding for the confirmation page).
	r.With(a.bindBrowser, a.logoutContext).Handle("/oidc/logout", a.provider)
	r.With(a.checkBrowser).Handle("/oidc/authorize/callback", a.provider)
	r.Handle("/oidc/*", a.provider)
	return r
}

// issuer returns the issuer of a realm: PUBLIC_URL/r/<realm>.
func (a *Adapter) issuer(realmName string) string {
	return a.base + "/r/" + url.PathEscape(realmName)
}

func (a *Adapter) issuerFromRequest(bool) (op.IssuerFromRequest, error) {
	return func(r *http.Request) string {
		realm, _ := realmFrom(r.Context())
		return a.issuer(realm.Name)
	}, nil
}

func checkPublicURL(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("oidc: PUBLIC_URL %q must be an absolute URL such as https://sso.example.com", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("oidc: PUBLIC_URL %q must not have a query, fragment or user info", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	default:
		return "", fmt.Errorf("oidc: PUBLIC_URL %q must use https (http is only allowed in development)", raw)
	}
	return u.String(), nil
}

func (a *Adapter) requireRealm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := realmFrom(r.Context()); !ok {
			a.logger.ErrorContext(r.Context(), "oidc: handler called without a realm in the context")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders for every OIDC response. The pages set their own CSP.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		// The login URL carries the request id: do not leak it to other sites.
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// handleDiscovery: the library's discovery document, corrected to announce
// only what this IdP really accepts (it lists implicit, device and JWT
// profile flows by default).
func (a *Adapter) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	realm, _ := realmFrom(r.Context())
	ctx := op.ContextWithIssuer(r.Context(), a.issuer(realm.Name))
	d := op.CreateDiscoveryConfig(ctx, a.provider, a.storage)

	d.ResponseTypesSupported = []string{string(oidc.ResponseTypeCode)}
	d.ResponseModesSupported = []string{string(oidc.ResponseModeQuery), string(oidc.ResponseModeFormPost)}
	d.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
	d.SubjectTypesSupported = []string{"public", "pairwise"}
	d.CodeChallengeMethodsSupported = []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256}
	d.TokenEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodNone}
	d.RevocationEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodNone}
	d.IntrospectionEndpointAuthMethodsSupported = []oidc.AuthMethod{oidc.AuthMethodBasic}
	d.TokenEndpointAuthSigningAlgValuesSupported = nil
	d.RevocationEndpointAuthSigningAlgValuesSupported = nil
	d.IntrospectionEndpointAuthSigningAlgValuesSupported = nil
	d.RequestObjectSigningAlgValuesSupported = nil
	d.RequestParameterSupported = false
	d.DeviceAuthorizationEndpoint = ""
	d.CheckSessionIframe = ""
	d.UILocalesSupported = nil
	d.ScopesSupported = supportedScopes
	d.ClaimsSupported = supportedClaims

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(d); err != nil {
		a.logger.WarnContext(r.Context(), "oidc: write discovery document", "error", err)
	}
}

// codeCrypto is the library's "Crypto". It is only used to build
// authorization codes (we issue JWT access tokens, never its opaque
// encrypted ones): Encrypt returns a fresh random code, unrelated to the
// request id, which travels in the login page URL. Decrypt fails, which the
// library reads as "not one of my opaque tokens".
type codeCrypto struct{}

func (codeCrypto) Encrypt(string) (string, error) { return rand.Text() + rand.Text(), nil }
func (codeCrypto) Decrypt(string) (string, error) {
	return "", errors.New("oidc: opaque tokens are not used")
}
