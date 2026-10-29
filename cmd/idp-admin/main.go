package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sso.internal/sso/internal/adminapi"
	"sso.internal/sso/internal/app"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/notify"
)

const usage = `usage:
  idp-admin [serve]
  idp-admin bootstrap --email <address> [--username <name>] [--admin-url <url of the admin console>]
  idp-admin recover admin --email <address>
  idp-admin recover client-secret
  idp-admin recover timeouts

environment (besides DATABASE_URL, VALKEY_ADDR, KEYMANAGER_BACKEND... shared with idp):
  ADMIN_API_ADDR            listen address of the Admin API (default :8090)
  ADMIN_API_ALLOWED_CIDRS   who may call it, e.g. 10.0.2.15/32,10.0.3.0/24 (required in production)
  ADMIN_PANEL_URL           URL of the admin console (default http://localhost:3000)
  IDP_INTERNAL_URL          how this server reaches idp, for the dashboard (default http://localhost:$PORT)
  ADMIN_API_LOG_REQUESTS    true: log every call with its duration (slow calls, 500 ms and more, always are)
`

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve()
	case "bootstrap":
		os.Exit(runBootstrap(os.Args[2:]))
	case "recover":
		os.Exit(runRecover(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func serve() {
	addr := os.Getenv("ADMIN_API_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	nets, err := allowedNets(os.Getenv("ADMIN_API_ALLOWED_CIDRS"))
	if err != nil {
		log.Fatalf("ADMIN_API_ALLOWED_CIDRS: %v", err)
	}
	if len(nets) == 0 {
		if os.Getenv("APP_ENV") == "production" {
			log.Fatalf("ADMIN_API_ALLOWED_CIDRS is required when APP_ENV=production: list the address(es) of the admin console's server")
		}
		log.Printf("ADMIN_API_ALLOWED_CIDRS is not set: any address may call the Admin API (development only)")
	}

	c := app.BuildCore()
	defer c.Close()

	var testEmail func(ctx context.Context, to string) error
	if sender := app.EmailSender(app.Templates()); sender != nil {
		testEmail = func(ctx context.Context, to string) error {
			return sender.Send(ctx, to, notify.TemplateTest, notify.Data{
				Product: "Oh-My-SSO", When: time.Now().UTC().Format("Mon 2 Jan 2006, 15:04 UTC"),
			})
		}
	}

	admin, rights := c.AdminService(), valkeycache.NewRightsEpoch(c.Valkey)
	syncAdminCatalogue(admin, rights)
	c.StartTimeoutEnforcer()

	api := adminapi.New(adminapi.Config{PublicURL: c.PublicURL, AllowedNets: nets, KMSBackend: c.KMSBackend,
		LogRequests: os.Getenv("ADMIN_API_LOG_REQUESTS") == "true"}, adminapi.Deps{
		Admin: admin, Realms: c.Realms, Users: c.Users, Clients: c.Clients, Tokens: c.Tokens,
		Sessions: c.Sessions, RBAC: c.RBAC, MFA: c.MFA, Keys: c.IdentityCore, KeyRotation: c.KeyRotation,
		Health: healthChecks(c), TestEmail: testEmail, Rights: rights,
	})

	srv := &http.Server{Addr: addr, Handler: api.Router(), ReadHeaderTimeout: 10 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	log.Printf("Admin API listening on %s (issuer of admin tokens: %s/r/master)", addr, c.PublicURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// syncAdminCatalogue gives the system groups of the master realm the
// permissions added by an upgrade (they would otherwise reach nobody: the
// bootstrap runs once). When a group changed, the rights epoch moves so that
// admin tokens issued before are checked against the database again. A
// failure is logged: the Admin API still starts, with the old permissions.
func syncAdminCatalogue(admin interface {
	SyncAdminCatalogue(context.Context) (bool, error)
}, rights adminapi.RightsEpoch) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	changed, err := admin.SyncAdminCatalogue(ctx)
	if err != nil {
		log.Printf("admin permissions: cannot bring the catalogue up to date: %v", err)
		return
	}
	if !changed {
		return
	}
	if err := rights.Changed(ctx, time.Now()); err != nil {
		log.Printf("admin permissions: updated, but the rights epoch could not move (%v): "+
			"administrators see the new permissions at their next sign-in", err)
		return
	}
	log.Printf("admin permissions: the admins and auditors groups now have every permission of this version")
}

// allowedNets parses "10.0.0.5, 10.1.0.0/16": IPs become /32 (or /128).
func allowedNets(v string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("%q is neither an IP nor a CIDR", part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			part = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("%q: %v", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// healthChecks: the "Infrastructure" line of the dashboard.
func healthChecks(c *app.Core) []adminapi.HealthCheck {
	idpURL := strings.TrimRight(os.Getenv("IDP_INTERNAL_URL"), "/")
	if idpURL == "" {
		idpURL = "http://localhost:" + app.IdPPort()
	}
	smtpAddr := app.SMTPAddress()
	return []adminapi.HealthCheck{
		{Name: "PostgreSQL", Check: func(ctx context.Context) error {
			_, err := c.Ent.Realm.Query().Exist(ctx)
			return err
		}},
		{Name: "Valkey", Check: func(ctx context.Context) error {
			return c.Valkey.Do(ctx, c.Valkey.B().Ping().Build()).Error()
		}},
		{Name: "Key manager (" + c.KMSBackend + ")", Check: func(ctx context.Context) error {
			// A real signature with the master realm's JWT key: proves the
			// KMS answers and holds the key.
			master, err := c.Realms.GetByName(ctx, "master")
			if err != nil {
				return err
			}
			keys, err := c.SigningKeys.ListByRealm(ctx, master.ID)
			if err != nil {
				return err
			}
			for _, k := range keys {
				if k.Status == domain.SigningKeyActive && k.Purpose == domain.SigningKeyPurposeJWT {
					_, err := c.KeyManager.Sign(ctx, k.KMSKeyReference, []byte("omsso-health"))
					return err
				}
			}
			return errors.New("the master realm has no active signing key")
		}},
		{Name: "Public server (OIDC, SAML)", Check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, idpURL+"/health", nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil
		}},
		{Name: "Notifications (SMTP)", Check: func(ctx context.Context) error {
			if smtpAddr == "" {
				return adminapi.ErrDisabled
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", smtpAddr)
			if err != nil {
				return err
			}
			return conn.Close()
		}},
	}
}
