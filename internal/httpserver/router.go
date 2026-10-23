package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ratelimit"
)

type Server struct {
	router      *chi.Mux
	auth        *service.AuthService
	sessions    *service.SessionService
	authz       Authorizer
	realms      repository.RealmRepository
	clients     repository.ClientRepository
	rateLimiter ratelimit.Limiter

	// Optional, set with options (Step 8). Their routes are only mounted
	// when provided, so existing callers of New keep working unchanged.
	publicKeys PublicKeySource
	// Step 14: the signing key admin endpoints moved to the Admin API
	// (internal/adminapi, cmd/idp-admin). This server is reachable by end
	// users and exposes no admin route.

	// Step 9: MFA. nil = no second factor anywhere (earlier steps' tests).
	mfa      *service.MFAService
	devPages bool

	// Step 10: OpenID Connect. nil = no OIDC routes.
	oidc OIDCProvider

	// Step 11: SAML 2.0. nil = no SAML routes.
	saml SAMLProvider

	// Step 12: password reset. nil = no forgot/reset routes.
	passwordReset *service.PasswordResetService
	// Step 14: "forgot password" (needs e-mail). The "choose a password"
	// page is mounted whenever passwordReset is set: activation links of
	// new accounts (bootstrap, invitations) use it too.
	forgotPassword bool
}

// OIDCProvider is the OIDC adapter as the router sees it (implemented by
// internal/adapters/oidc).
type OIDCProvider interface {
	// Handler serves /r/{realm}/oidc/*.
	Handler() http.Handler
	// DiscoveryHandler serves /r/{realm}/.well-known/openid-configuration.
	DiscoveryHandler() http.Handler
}

// SAMLProvider is the SAML adapter as the router sees it (implemented by
// internal/adapters/saml).
type SAMLProvider interface {
	// Handler serves /r/{realm}/saml/*.
	Handler() http.Handler
}

// Option configures optional parts of the Server.
type Option func(*Server)

// WithJWKS mounts GET /r/{realm}/.well-known/jwks.json.
func WithJWKS(src PublicKeySource) Option {
	return func(s *Server) { s.publicKeys = src }
}

// WithMFA turns on the second factor: login challenge, step-up, account
// MFA routes, and step-up on sensitive admin routes.
func WithMFA(mfa *service.MFAService) Option {
	return func(s *Server) { s.mfa = mfa }
}

// WithOIDC mounts the OpenID Connect endpoints (Step 10): discovery and
// /r/{realm}/oidc/... (authorize, login page, token, userinfo, revoke,
// introspect, logout).
func WithOIDC(p OIDCProvider) Option {
	return func(s *Server) { s.oidc = p }
}

// WithSAML mounts the SAML 2.0 endpoints (Step 11): /r/{realm}/saml/...
// (metadata, sso, login page, slo).
func WithSAML(p SAMLProvider) Option {
	return func(s *Server) { s.saml = p }
}

// WithPasswordReset mounts the reset-password page and its JSON endpoint
// (Step 12): reset links from e-mails, and activation links (Step 14).
func WithPasswordReset(p *service.PasswordResetService) Option {
	return func(s *Server) { s.passwordReset = p }
}

// WithForgotPassword also mounts the "forgot password" page and endpoint,
// which send a reset link by e-mail. Only when e-mails can leave the server.
func WithForgotPassword(enabled bool) Option {
	return func(s *Server) { s.forgotPassword = enabled }
}

// WithDevPages mounts /r/{realm}/dev/mfa, a bare HTML page to try the MFA
// flows by hand. Only ever enabled when APP_ENV=development.
func WithDevPages(enabled bool) Option {
	return func(s *Server) { s.devPages = enabled }
}

func New(
	auth *service.AuthService,
	sessions *service.SessionService,
	authz Authorizer,
	realms repository.RealmRepository,
	clients repository.ClientRepository,
	rateLimiter ratelimit.Limiter,
	opts ...Option,
) *Server {
	s := &Server{
		router:      chi.NewRouter(),
		auth:        auth,
		sessions:    sessions,
		authz:       authz,
		realms:      realms,
		clients:     clients,
		rateLimiter: rateLimiter,
	}
	for _, opt := range opts {
		opt(s)
	}

	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Recoverer)

	s.router.Get("/health", s.handleHealth)

	s.router.Route("/r/{realmName}", func(r chi.Router) {
		r.Use(s.realmMiddleware)
		s.mountAuth(r)
		if s.passwordReset != nil {
			s.mountPasswordReset(r)
		}
		if s.mfa != nil {
			s.mountMFA(r)
			if s.mfa.PasskeysEnabled() {
				s.mountWebAuthn(r)
			}
			if s.devPages {
				s.mountDevPages(r)
			}
		}
		if s.publicKeys != nil {
			s.mountJWKS(r)
		}
		if s.oidc != nil {
			s.mountOIDC(r)
		}
		if s.saml != nil {
			s.mountSAML(r)
		}
	})

	return s
}

func (s *Server) Router() *chi.Mux {
	return s.router
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
