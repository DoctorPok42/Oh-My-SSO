// Package app is the start-up wiring shared by the two binaries (Step 14):
//
//	cmd/idp        public authentication (login, OIDC, SAML) and account pages
//	cmd/idp-admin  the Admin API used by the admin panel, plus bootstrap/recover
//
// Both run the same core (internal/core) on the same database: this package
// reads the environment once and builds the dependencies in one place, so
// the two binaries cannot drift apart.
//
// It is only meant for cmd/: like the code it came from (cmd/idp/main.go
// before Step 14), it stops the process with log.Fatal on a configuration
// error. A server that starts half-configured is worse than one that does
// not start.
package app

import (
	"database/sql"
	"encoding/base64"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/geoip"
	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/keymanager/ovhkms"
	"sso.internal/sso/internal/keymanager/vault"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/passkey"
)

// BackendLocalDev is the in-memory KeyManager (development only).
const BackendLocalDev = "local_dev"

// EntClient opens the database (DATABASE_URL).
func EntClient() *ent.Client {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	drv := entsql.OpenDB(dialect.Postgres, db)
	return ent.NewClient(ent.Driver(drv))
}

// KeyManager returns the KeyManager and the backend name stored on each
// SigningKey it creates (SigningKey.kms_backend).
func KeyManager() (keymanager.KeyManager, string) {
	switch backend := os.Getenv("KEYMANAGER_BACKEND"); backend {
	case "vault":
		km, err := vault.New(vault.Config{
			Address: os.Getenv("VAULT_ADDR"),
			Token:   os.Getenv("VAULT_TOKEN"),
		})
		if err != nil {
			log.Fatalf("keymanager: %v", err)
		}
		return km, backend
	case "ovhkms":
		okmsID, err := uuid.Parse(os.Getenv("OVHKMS_DOMAIN_ID"))
		if err != nil {
			log.Fatalf("keymanager: invalid OVHKMS_DOMAIN_ID: %v", err)
		}
		km, err := ovhkms.New(ovhkms.Config{
			Endpoint:       os.Getenv("OVHKMS_ENDPOINT"),
			OkmsID:         okmsID,
			ClientCertFile: os.Getenv("OVHKMS_CLIENT_CERT_FILE"),
			ClientKeyFile:  os.Getenv("OVHKMS_CLIENT_KEY_FILE"),
		})
		if err != nil {
			log.Fatalf("keymanager: %v", err)
		}
		return km, backend
	case BackendLocalDev, "":
		var opts []localdev.Option
		if raw := os.Getenv("LOCALDEV_ENVELOPE_KEY"); raw != "" {
			key, err := base64.StdEncoding.DecodeString(raw)
			if err != nil || len(key) != 32 {
				log.Fatalf("keymanager: LOCALDEV_ENVELOPE_KEY must be 32 bytes, base64 encoded (openssl rand -base64 32)")
			}
			opts = append(opts, localdev.WithEnvelopeMasterKey(key))
		} else {
			log.Printf("keymanager: LOCALDEV_ENVELOPE_KEY is not set: TOTP secrets enrolled now will be unreadable after a restart")
		}
		return localdev.New(os.Getenv("APP_ENV"), opts...), BackendLocalDev
	default:
		log.Fatalf("keymanager: unknown backend %q", backend)
		return nil, ""
	}
}

// Passkeys returns the WebAuthn engine, or nil (passkeys disabled) when
// WEBAUTHN_RP_ID is not set.
//
//	WEBAUTHN_RP_ID=localhost
//	WEBAUTHN_RP_ORIGINS=http://localhost:8080          (comma separated)
//	WEBAUTHN_RP_DISPLAY_NAME=Oh-My-SSO                  (optional)
func Passkeys() service.PasskeyProvider {
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		log.Printf("passkeys: disabled (set WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGINS to enable them)")
		return nil
	}
	var origins []string
	for _, o := range strings.Split(os.Getenv("WEBAUTHN_RP_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	p, err := passkey.New(passkey.Config{
		RPID:          rpID,
		RPDisplayName: os.Getenv("WEBAUTHN_RP_DISPLAY_NAME"),
		RPOrigins:     origins,
	})
	if err != nil {
		log.Fatalf("passkeys: %v", err)
	}
	return p
}

// PublicURL returns the external URL of the public server (cmd/idp), used
// by the OIDC and SAML adapters, in e-mails, and by the Admin API to check
// the issuer of admin tokens and to build activation links.
//
//	PUBLIC_URL=https://sso.example.com   external URL of the public server; the
//	                                     issuer of a realm is PUBLIC_URL/r/<realm>
//
// Without PUBLIC_URL (development only) it is http://localhost:<PORT>
// (PORT of cmd/idp, default 8080). http:// is refused when
// APP_ENV=production: OIDC requires https issuers, and SAML messages
// carrying assertions must not travel in clear.
func PublicURL() string {
	publicURL := os.Getenv("PUBLIC_URL")
	if publicURL == "" {
		if os.Getenv("APP_ENV") == "production" {
			log.Fatalf("PUBLIC_URL is required when APP_ENV=production")
		}
		publicURL = "http://localhost:" + IdPPort()
		log.Printf("PUBLIC_URL is not set, using %s (development only)", publicURL)
	}
	return strings.TrimRight(publicURL, "/")
}

// DevPublicURL is PublicURL without the log lines and checks, for CLI output.
func DevPublicURL() string {
	if u := os.Getenv("PUBLIC_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:" + IdPPort()
}

// IdPPort is the port of cmd/idp (PORT, default 8080).
func IdPPort() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "8080"
}

// GeoIP opens the country database for the "new country" signal (Step 12).
// GEOIP_DB_PATH=/path/to/dbip-country-lite.mmdb; unset = off. It returns a
// nil interface (not a typed nil pointer) when off.
func GeoIP() service.GeoIPResolver {
	path := os.Getenv("GEOIP_DB_PATH")
	if path == "" {
		log.Printf("geoip: GEOIP_DB_PATH is not set: no \"new country\" signal on sign-ins")
		return nil
	}
	r, err := geoip.Open(path)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("geoip: %s", r.Description())
	return r
}

// --- e-mail (Step 12) -----------------------------------------------------------
//
//	SMTP_HOST=mail.example.com        no SMTP_HOST: development prints e-mails in the
//	                                  log; production sends none (and turns off
//	                                  "forgot password", which needs e-mail)
//	SMTP_PORT=587                     default 587 (465 with SMTP_SECURITY=tls)
//	SMTP_SECURITY=starttls            starttls | tls | none (none: localhost only in production)
//	SMTP_USERNAME= / SMTP_PASSWORD=   empty: no authentication
//	SMTP_FROM=Oh-My-SSO <no-reply@example.com>     required in production
//	SMTP_HELO_NAME=                   name announced in EHLO (default "localhost")

// EmailSender returns the sender configured by SMTP_*, or nil when e-mail
// is off.
func EmailSender(templates *notify.Templates) notify.EmailSender {
	appEnv := os.Getenv("APP_ENV")
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		if appEnv == "development" {
			log.Printf("mail: SMTP_HOST is not set: e-mails are printed in this log instead (development only)")
			return &notify.LogEmailSender{Templates: templates, Logger: nil}
		}
		log.Printf("mail: SMTP_HOST is not set: no e-mail is sent, \"forgot password\" is disabled")
		return nil
	}

	port := 0
	if p := os.Getenv("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			log.Fatalf("mail: SMTP_PORT %q is not a number", p)
		}
		port = n
	}
	from := Unquote(os.Getenv("SMTP_FROM"))
	if from == "" {
		if appEnv == "production" {
			log.Fatalf("mail: SMTP_FROM is required when APP_ENV=production")
		}
		from = "Oh-My-SSO <no-reply@localhost>"
	}
	security := notify.Security(strings.ToLower(os.Getenv("SMTP_SECURITY")))
	if security == notify.SecurityNone && appEnv == "production" && !isLoopbackHost(host) {
		log.Fatalf("mail: SMTP_SECURITY=none sends passwords and reset links in clear: refused in production (except to localhost)")
	}

	sender, err := notify.NewSMTPEmailSender(notify.SMTPConfig{
		Host:     host,
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		Security: security,
		From:     from,
		HeloName: os.Getenv("SMTP_HELO_NAME"),
	}, templates)
	if err != nil {
		log.Fatalf("mail: %v", err)
	}
	cfg := sender.Config()
	log.Printf("mail: SMTP %s:%d (%s), from %s", cfg.Host, cfg.Port, cfg.Security, cfg.From)
	return sender
}

// SMTPAddress is host:port of the configured mail server ("" when e-mail is
// off or printed in the log). The admin dashboard dials it to show its status.
func SMTPAddress() string {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return ""
	}
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
		if strings.EqualFold(os.Getenv("SMTP_SECURITY"), string(notify.SecurityTLS)) {
			port = "465"
		}
	}
	return net.JoinHostPort(host, port)
}

// Unquote removes quotes around a whole value (SMTP_FROM="A <a@b>" read by
// a tool that keeps them, like make), but not quotes inside it.
func Unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Templates parses the embedded e-mail templates.
func Templates() *notify.Templates {
	t, err := notify.LoadTemplates()
	if err != nil {
		log.Fatalf("mail: %v", err) // embedded files: only a broken build gets here
	}
	return t
}
