package adminapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// Config of the Admin API.
type Config struct {
	// PublicURL of cmd/idp: the admin tokens' issuer is PublicURL/r/master.
	PublicURL string
	// AllowedNets: callers allowed by IP. Empty: any (development only;
	// cmd/idp-admin refuses an empty list in production).
	AllowedNets []*net.IPNet
	// KMSBackend: with "local_dev" the private keys live in the memory of
	// one process; keys created here could never sign on the public server,
	// so rotations are refused.
	KMSBackend string
	// LogRequests: log every call with its duration (slow ones always are).
	LogRequests bool
	Now         func() time.Time
}

// Authorizer is the RBAC check (service.RBACService).
type Authorizer interface {
	// Authorize checks one permission; a refusal is written to the audit log.
	Authorize(ctx context.Context, in service.AuthorizeInput) error
	// GetEffectivePermissions lists every permission at once, without audit
	// entries: GET /me asks "what may I do", it does not attempt anything.
	GetEffectivePermissions(ctx context.Context, userID, clientRef string) ([]*domain.Permission, error)
}

// HealthCheck is one line of the dashboard's infrastructure status.
type HealthCheck struct {
	Name string
	// Check returns nil when healthy. ErrDisabled: not configured.
	Check func(ctx context.Context) error
}

// Deps of the Admin API.
type Deps struct {
	Admin       *service.AdminService
	Realms      repository.RealmRepository
	Users       repository.UserRepository
	Clients     repository.ClientRepository
	Tokens      repository.TokenRepository
	Sessions    *service.SessionService
	RBAC        Authorizer
	MFA         *service.MFAService
	Keys        PublicKeySource
	KeyRotation *service.KeyRotationService
	Health      []HealthCheck
	// TestEmail sends the "test" e-mail; nil when e-mail is off.
	TestEmail func(ctx context.Context, to string) error
	// Rights: when the master realm last changed, shared by every idp-admin
	// process (rights.go). nil: kept in this process only.
	Rights RightsEpoch
}

// Server is the Admin API.
type Server struct {
	cfg      Config
	d        Deps
	verifier *tokenVerifier
	router   *chi.Mux

	identity struct { // see adminIdentity
		mu     sync.Mutex
		master *domain.Realm
		client *domain.ClientApp
		at     time.Time
	}
	healthCache struct { // see cachedHealth
		mu    sync.Mutex
		lines []healthLine
		at    time.Time
	}
}

const (
	identityCacheTTL = time.Minute
	// healthCacheTTL: the dashboard's infrastructure checks (a real signature
	// by the KMS, a call to idp, an SMTP connection...) run at most this often.
	healthCacheTTL = 15 * time.Second
)

func (s *Server) now() time.Time { return s.cfg.Now() }

// New builds the router.
func New(cfg Config, d Deps) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if d.Rights == nil {
		d.Rights = &memoryEpoch{at: cfg.Now()}
	}
	s := &Server{cfg: cfg, d: d, router: chi.NewRouter()}
	s.verifier = &tokenVerifier{keys: d.Keys, issuer: trimSlash(cfg.PublicURL) + "/r/" + service.MasterRealmName,
		audience: "sso-admin", now: cfg.Now}

	r := s.router
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(s.logSlow)
	r.Use(securityHeaders)
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.allowlist, requireJSON, s.authenticate)
		r.Get("/me", s.handleMe)

		r.With(s.require("realm", "read")).Get("/realms", s.handleListRealms)
		r.With(s.require("realm", "write"), s.stepUp).Post("/realms", s.handleCreateRealm)

		r.Route("/realms/{realm}", func(r chi.Router) {
			r.Use(s.loadRealm)
			read := func(res string) func(http.Handler) http.Handler { return s.require(res, "read") }
			write := func(res, action string) chi.Middlewares {
				return chi.Middlewares{s.require(res, action), s.stepUp, s.recordRightsChange}
			}

			r.With(read("realm")).Get("/", s.handleGetRealm)
			r.With(write("realm", "write")...).Patch("/", s.handleUpdateRealm)
			r.With(read("realm")).Get("/dashboard", s.handleDashboard)

			r.With(read("client")).Get("/clients", s.handleListClients)
			r.With(write("client", "write")...).Post("/clients", s.handleCreateClient)
			r.With(read("client")).Get("/clients/{id}", s.handleGetClient)
			r.With(write("client", "write")...).Patch("/clients/{id}", s.handleUpdateClient)
			r.With(write("client", "write")...).Delete("/clients/{id}", s.handleDeleteClient)
			r.With(write("client", "write")...).Post("/clients/{id}/secret", s.handleRotateSecret)
			r.With(write("client", "write")...).Post("/clients/{id}/certificates", s.handleAddCertificate)
			r.With(write("client", "write")...).Delete("/clients/{id}/certificates/{fingerprint}", s.handleRemoveCertificate)

			r.With(read("client_scope")).Get("/client-scopes", s.handleListScopes)
			r.With(write("client_scope", "write")...).Post("/client-scopes", s.handleCreateScope)
			r.With(read("client_scope")).Get("/client-scopes/{id}", s.handleGetScope)
			r.With(write("client_scope", "write")...).Patch("/client-scopes/{id}", s.handleUpdateScope)
			r.With(write("client_scope", "write")...).Delete("/client-scopes/{id}", s.handleDeleteScope)

			r.With(read("session")).Get("/sessions", s.handleListSessions)
			r.With(write("session", "revoke")...).Delete("/sessions/{id}", s.handleRevokeSession)

			r.With(read("audit_log")).Get("/audit-logs", s.handleAuditLogs)

			r.With(read("user")).Get("/users", s.handleListUsers)
			r.With(write("user", "write")...).Post("/users", s.handleInviteUser)
			r.With(read("user")).Get("/users/{id}", s.handleGetUser)
			r.With(write("user", "write")...).Patch("/users/{id}", s.handleUpdateUser)
			r.With(write("user", "write")...).Delete("/users/{id}", s.handleDeleteUser)
			r.With(write("user", "write")...).Put("/users/{id}/groups", s.handleSetUserGroups)
			r.With(write("user", "write")...).Put("/users/{id}/roles", s.handleSetUserRoles)
			r.With(write("user", "write")...).Post("/users/{id}/mfa/reset", s.handleResetUserMFA)
			r.With(write("user", "write")...).Post("/users/{id}/unlock", s.handleUnlockUser)
			r.With(write("user", "write")...).Post("/users/{id}/activation-link", s.handleActivationLink)
			r.With(write("session", "revoke")...).Delete("/users/{id}/sessions", s.handleRevokeUserSessions)
			r.With(write("session", "revoke")...).Delete("/users/{id}/trusted-devices", s.handleRevokeTrustedDevices)
			r.With(write("session", "revoke")...).Delete("/users/{id}/trusted-devices/{deviceID}", s.handleRevokeTrustedDevice)

			r.With(read("access")).Get("/roles", s.handleListRoles)
			r.With(write("access", "write")...).Post("/roles", s.handleCreateRole)
			r.With(write("access", "write")...).Patch("/roles/{id}", s.handleUpdateRole)
			r.With(write("access", "write")...).Delete("/roles/{id}", s.handleDeleteRole)
			r.With(read("access")).Get("/groups", s.handleListGroups)
			r.With(write("access", "write")...).Post("/groups", s.handleCreateGroup)
			r.With(write("access", "write")...).Patch("/groups/{id}", s.handleUpdateGroup)
			r.With(write("access", "write")...).Delete("/groups/{id}", s.handleDeleteGroup)
			r.With(read("access")).Get("/groups/{id}/members", s.handleGroupMembers)
			r.With(read("access")).Get("/permissions", s.handleListPermissions)
			r.With(write("access", "write")...).Post("/permissions", s.handleCreatePermission)
			r.With(write("access", "write")...).Delete("/permissions/{id}", s.handleDeletePermission)

			r.With(read("signing_key")).Get("/signing-keys", s.handleListKeys)
			r.With(write("signing_key", "rotate")...).Post("/signing-keys/rotate", s.handleRotateKey)
			r.With(write("signing_key", "rotate")...).Post("/signing-keys/activate", s.handleActivateKey)
			r.With(write("signing_key", "rotate")...).Post("/signing-keys/retire-expired", s.handleRetireKeys)

			r.With(read("mfa_policy")).Get("/mfa-policies", s.handleMFAPolicies)
			r.With(write("mfa_policy", "write")...).Put("/mfa-policies/realm", s.handleSetRealmMFA)
			r.With(write("mfa_policy", "write")...).Put("/mfa-policies/roles/{id}", s.handleSetRoleMFA)
			r.With(write("mfa_policy", "write")...).Delete("/mfa-policies/roles/{id}", s.handleDeleteRoleMFA)

			r.With(read("settings")).Get("/settings", s.handleGetSettings)
			r.With(write("settings", "write")...).Patch("/settings", s.handleUpdateSettings)
			r.With(write("settings", "write")...).Post("/settings/test-email", s.handleTestEmail)

			r.With(read("timeout")).Get("/timeouts", s.handleTimeouts)
		})
	})
	return s
}

// Router is the HTTP handler of the Admin API.
func (s *Server) Router() http.Handler { return s.router }

// slowRequest: a call slower than this is logged (WARN) with its duration,
// to find what makes a console page slow. ADMIN_API_LOG_REQUESTS=true
// (Config.LogRequests) logs every call.
const slowRequest = 500 * time.Millisecond

func (s *Server) logSlow(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		d := time.Since(start)
		switch {
		case d >= slowRequest:
			slog.WarnContext(r.Context(), "admin api: slow request", "method", r.Method, "path", r.URL.Path,
				"status", ww.Status(), "duration_ms", d.Milliseconds())
		case s.cfg.LogRequests:
			slog.InfoContext(r.Context(), "admin api", "method", r.Method, "path", r.URL.Path,
				"status", ww.Status(), "duration_ms", d.Milliseconds())
		}
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
