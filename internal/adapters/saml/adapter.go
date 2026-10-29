package saml

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/oidcstore"
)

// Config of the adapter. Everything comes from the server's environment.
type Config struct {
	// PublicURL is the external base URL of the IdP, e.g.
	// "https://sso.example.com" (same value as for OIDC). It is configured,
	// never taken from the Host header: the entity ID and every URL we sign
	// derive from it.
	PublicURL string
	// AllowInsecureHTTP accepts an http:// PublicURL (development only).
	AllowInsecureHTTP bool
	// SessionCookieName is the SSO session cookie (httpserver.SessionCookieName).
	SessionCookieName string
	// DeviceCookieName identifies the browser (httpserver.DeviceCookieName):
	// the accounts of "Pick an account" are remembered per device.
	DeviceCookieName string
	// PasskeysEnabled shows the passkey buttons on the sign-in page.
	PasskeysEnabled bool
	// DevPages links to /r/{realm}/dev/mfa when a factor must be enrolled
	// first (APP_ENV=development).
	DevPages bool
	PasswordReset bool
	// Now is the clock (tests). nil: time.Now.
	Now func() time.Time
	// Logger: nil means slog.Default().
	Logger *slog.Logger
}

// Adapter is the SAML 2.0 Identity Provider. Mount Handler() on
// /r/{realm}/saml/*, after putting the realm in the request context
// (WithRealm).
type Adapter struct {
	cfg     Config
	base    string // PublicURL without trailing slash
	core    core.IdentityCore
	store   oidcstore.Store
	logger  *slog.Logger
	now     func() time.Time
	pages   *loginui.Pages
	handler http.Handler
}

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
	a.handler = a.routes()
	return a, nil
}

// Handler serves /r/{realm}/saml/*. It expects to be mounted in a chi
// router under /r/{realmName} (it routes on the remaining path).
func (a *Adapter) Handler() http.Handler { return a.handler }

func (a *Adapter) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(a.requireRealm, securityHeaders)
	r.Get("/saml/metadata", a.handleMetadata)
	r.Get("/saml/sso", a.handleSSO)
	r.Post("/saml/sso", a.handleSSO)
	r.Get("/saml/login", a.handleLogin)
	r.Post("/saml/consent", a.handleConsent)
	r.Get("/saml/slo", a.handleSLO)
	r.Post("/saml/slo", a.handleSLO)
	r.Get("/saml/logged-out", a.handleLoggedOut)
	r.Get("/saml/assets/{file}", func(w http.ResponseWriter, r *http.Request) {
		loginui.Asset(w, r, chi.URLParam(r, "file"))
	})
	return r
}


func (a *Adapter) realmBase(realm Realm) string {
	return a.base + "/r/" + url.PathEscape(realm.Name) + "/saml"
}

// entityID is the IdP's name in SAML messages: the URL of its metadata, the
// usual convention (SimpleSAMLphp, crewjam). It must never change once
// service providers are configured: it is in every assertion they verify.
func (a *Adapter) entityID(realm Realm) string { return a.realmBase(realm) + "/metadata" }
func (a *Adapter) ssoURL(realm Realm) string   { return a.realmBase(realm) + "/sso" }
func (a *Adapter) sloURL(realm Realm) string   { return a.realmBase(realm) + "/slo" }

// assets is a path (same origin), used by the pages.
func assets(realm Realm) string { return "/r/" + realm.Name + "/saml/assets" }

func checkPublicURL(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("saml: PUBLIC_URL %q must be an absolute URL such as https://sso.example.com", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("saml: PUBLIC_URL %q must not have a query, fragment or user info", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	default:
		return "", fmt.Errorf("saml: PUBLIC_URL %q must use https (http is only allowed in development)", raw)
	}
	return u.String(), nil
}


// Realm is what the adapter needs to know about the realm of a request. The
// HTTP server resolves it from /r/{realm} and puts it in the context with
// WithRealm before calling the handlers.
type Realm struct {
	ID          string
	Name        string
	DisplayName string
}

type realmKey struct{}

// WithRealm returns a context that carries the realm of the request.
func WithRealm(ctx context.Context, r Realm) context.Context {
	return context.WithValue(ctx, realmKey{}, r)
}

func realmFrom(ctx context.Context) (Realm, bool) {
	r, ok := ctx.Value(realmKey{}).(Realm)
	return r, ok && r.ID != "" && r.Name != ""
}

func (a *Adapter) requireRealm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := realmFrom(r.Context()); !ok {
			a.logger.ErrorContext(r.Context(), "saml: handler called without a realm in the context")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders for every SAML response. The pages set their own CSP.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		// URLs carry SAML messages and request ids: never leak them.
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}


type message = loginui.Message

var (
	msgExpired = message{Title: "This sign-in link has expired",
		Text: "Go back to the application and start the sign-in again."}
	msgOtherBrowser = message{Title: "Sign-in started in another browser",
		Text: "For your security, a sign-in must be finished in the browser that started it. Go back to the application and start again here."}
	msgBadRequest = message{Title: "This sign-in request was refused",
		Text: "The application sent a request that this server cannot accept. Its administrator can find the reason in the server logs."}
	msgUnknownApp = message{Title: "Unknown application",
		Text: "This application is not registered on this server, or it is disabled."}
	msgLoggedOut     = message{Title: "You are signed out", Text: "You can close this window."}
	msgLogoutRefused = message{Title: "This sign-out request was refused",
		Text: "The application sent a sign-out request that this server cannot accept. Its administrator can find the reason in the server logs."}
	msgLogoutExpired = message{Title: "This sign-out has expired",
		Text: "You are signed out of this server. Some applications may still have you signed in: sign out of them directly."}
	msgNoKey = message{Title: "Single sign-on is not ready",
		Text: "This server has no SAML signing key yet. Its administrator must create one."}
)

func (a *Adapter) renderMessage(w http.ResponseWriter, r *http.Request, status int, m message) {
	realm, _ := realmFrom(r.Context())
	a.pages.RenderMessage(w, status, m, assets(realm))
}

func (a *Adapter) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	a.renderMessage(w, r, http.StatusOK, msgLoggedOut)
}

// currentSession is the valid SSO session of the browser, or nil.
func (a *Adapter) currentSession(r *http.Request, realm Realm) *domain.Session {
	c, err := r.Cookie(a.cfg.SessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := a.core.ValidateSession(r.Context(), realm.ID, c.Value)
	if err != nil {
		return nil
	}
	return sess
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
