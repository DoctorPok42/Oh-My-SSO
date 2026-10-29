package app

import (
	"database/sql"
	"encoding/base64"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/clientip"
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

// Connection pool (database/sql). Go keeps only 2 idle connections by
// default: as soon as a request runs a few queries at the same time (the
// Admin API's authentication, the dashboard), the extra connections are
// closed after use and opened again on the next request, each opening
// costing several round trips (TCP, PostgreSQL startup, SCRAM password
// exchange). Keeping more of them open removes that cost.
// https://pkg.go.dev/database/sql#DB.SetMaxIdleConns
const (
	dbMaxOpenConns    = 25 // per process: idp + idp-admin stay far below PostgreSQL's 100
	dbMaxIdleConns    = 10
	dbConnMaxIdleTime = 5 * time.Minute  // an unused connection is closed after that
	dbConnMaxLifetime = 30 * time.Minute // and every connection is renewed now and then
)

// EntClient opens the database (DATABASE_URL).
func EntClient() *ent.Client {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	db.SetMaxOpenConns(dbMaxOpenConns)
	db.SetMaxIdleConns(dbMaxIdleConns)
	db.SetConnMaxIdleTime(dbConnMaxIdleTime)
	db.SetConnMaxLifetime(dbConnMaxLifetime)
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

// ClientIP reads which reverse proxies may tell the client's address to
// cmd/idp (see internal/clientip):
//
//	TRUSTED_PROXIES=10.0.0.2,172.18.0.0/16  IPs or CIDRs of the proxies in front
//	                                        of cmd/idp, comma separated
//	CLIENT_IP_HEADER=X-Real-IP              optional: a single-IP header the proxy
//	                                        overwrites (default: X-Forwarded-For)
//
// Empty TRUSTED_PROXIES: the address is always the TCP peer and every
// forwarding header is ignored, the safe choice when browsers connect
// directly. Behind a proxy, leaving it empty makes every request look like
// it comes from the proxy, so all users share the per-IP rate limits.
func ClientIP() clientip.Resolver {
	res, err := clientip.Parse(os.Getenv("TRUSTED_PROXIES"), os.Getenv("CLIENT_IP_HEADER"))
	if err != nil {
		log.Fatalf("client ip: %v", err)
	}
	log.Print(res.String())
	return res
}

// ConfigurePasswordHashing reads how many password hashes (Argon2id, 64 MiB
// each) may be computed at the same time:
//
//	PASSWORD_HASH_CONCURRENCY=4   default; at most 4 x 64 MiB = 256 MiB of RAM
//
// More slots let more sign-ins run in parallel on a big server, at the cost
// of memory; extra sign-ins wait for a free slot instead of failing.
func ConfigurePasswordHashing() {
	n := service.DefaultPasswordHashConcurrency
	if v := os.Getenv("PASSWORD_HASH_CONCURRENCY"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 1 {
			log.Fatalf("PASSWORD_HASH_CONCURRENCY %q must be a whole number of at least 1", v)
		}
		n = parsed
	}
	service.SetPasswordHashConcurrency(n)
	log.Printf("passwords: Argon2id, at most %d hashes at a time (%d MiB of RAM)", n, n*service.PasswordHashMemoryMiB)
}

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
