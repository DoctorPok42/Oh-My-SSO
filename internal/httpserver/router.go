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
	keyRotator KeyRotator
}

// Option configures optional parts of the Server.
type Option func(*Server)

// WithJWKS mounts GET /r/{realm}/.well-known/jwks.json.
func WithJWKS(src PublicKeySource) Option {
	return func(s *Server) { s.publicKeys = src }
}

// WithSigningKeyAdmin mounts /r/{realm}/admin/signing-keys/... (RBAC protected).
func WithSigningKeyAdmin(rot KeyRotator) Option {
	return func(s *Server) { s.keyRotator = rot }
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
		if s.publicKeys != nil {
			s.mountJWKS(r)
		}
		if s.keyRotator != nil {
			s.mountSigningKeyAdmin(r)
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
