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
	router *chi.Mux
	auth   *service.AuthService
	realms repository.RealmRepository
	rateLimiter ratelimit.Limiter
}

func New(auth *service.AuthService, realms repository.RealmRepository, rateLimiter ratelimit.Limiter) *Server {
	s := &Server{
		router: chi.NewRouter(),
		auth:   auth,
		realms: realms,
		rateLimiter: rateLimiter,
	}

	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Recoverer)

	s.router.Get("/health", s.handleHealth)

	s.router.Route("/r/{realmName}", func(r chi.Router) {
		r.Use(s.realmMiddleware)
		s.mountAuth(r)
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
