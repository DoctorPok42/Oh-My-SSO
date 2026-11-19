package app

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/clientip"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/geoip"
	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/keymanager/ovhkms"
	"sso.internal/sso/internal/keymanager/vault"
	"sso.internal/sso/internal/logging"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/passkey"
	"sso.internal/sso/internal/storage/entstore"
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

// OpenDatabase opens the connection pool (DATABASE_URL).
func OpenDatabase() *sql.DB {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		logging.Fatal("db: cannot open", "error", err)
	}
	db.SetMaxOpenConns(dbMaxOpenConns)
	db.SetMaxIdleConns(dbMaxIdleConns)
	db.SetConnMaxIdleTime(dbConnMaxIdleTime)
	db.SetConnMaxLifetime(dbConnMaxLifetime)
	return db
}

// entClientOn is the ent client on db, and the transactions its
// repositories join (service.*Deps.Tx).
func entClientOn(db *sql.DB) (*ent.Client, repository.Transactor) {
	drv := entstore.NewDriver(db)
	return ent.NewClient(ent.Driver(drv)), drv
}

// EntClient opens the database (DATABASE_URL).
func EntClient() *ent.Client {
	client, _ := entClientOn(OpenDatabase())
	return client
}

// EntClientTx is EntClient, with the transactions its repositories join.
func EntClientTx() (*ent.Client, repository.Transactor) {
	return entClientOn(OpenDatabase())
}

// KeyManager returns the KeyManager and the backend name stored on each
// SigningKey it creates (SigningKey.kms_backend).
func KeyManager() (keymanager.KeyManager, string) {
	km, backend, err := NewKeyManager()
	if err != nil {
		logging.Fatal("keymanager: cannot start", "backend", backend, "error", err)
	}
	return km, backend
}

// NewKeyManager is KeyManager, returning the error (idp doctor).
func NewKeyManager() (keymanager.KeyManager, string, error) {
	switch backend := os.Getenv("KEYMANAGER_BACKEND"); backend {
	case "vault":
		km, err := vault.New(vault.Config{
			Address:             os.Getenv("VAULT_ADDR"),
			Token:               os.Getenv("VAULT_TOKEN"),
			MountPath:           os.Getenv("VAULT_TRANSIT_MOUNT"),
			Namespace:           os.Getenv("VAULT_NAMESPACE"),
			AppRoleID:           os.Getenv("VAULT_APPROLE_ROLE_ID"),
			AppRoleSecretID:     os.Getenv("VAULT_APPROLE_SECRET_ID"),
			AppRoleSecretIDFile: os.Getenv("VAULT_APPROLE_SECRET_ID_FILE"),
			AppRoleMountPath:    os.Getenv("VAULT_APPROLE_MOUNT"),
		})
		if err != nil {
			return nil, backend, err
		}
		return km, backend, nil
	case "ovhkms":
		okmsID, err := uuid.Parse(os.Getenv("OVHKMS_DOMAIN_ID"))
		if err != nil {
			return nil, backend, fmt.Errorf("invalid OVHKMS_DOMAIN_ID: %w", err)
		}
		km, err := ovhkms.New(ovhkms.Config{
			Endpoint:       os.Getenv("OVHKMS_ENDPOINT"),
			OkmsID:         okmsID,
			ClientCertFile: os.Getenv("OVHKMS_CLIENT_CERT_FILE"),
			ClientKeyFile:  os.Getenv("OVHKMS_CLIENT_KEY_FILE"),
		})
		if err != nil {
			return nil, backend, err
		}
		return km, backend, nil
	case BackendLocalDev, "":
		if os.Getenv("APP_ENV") == "production" {
			return nil, BackendLocalDev, errors.New("the local_dev backend is refused when APP_ENV=production: set KEYMANAGER_BACKEND to vault or ovhkms")
		}
		var opts []localdev.Option
		if raw := os.Getenv("LOCALDEV_ENVELOPE_KEY"); raw != "" {
			key, err := base64.StdEncoding.DecodeString(raw)
			if err != nil || len(key) != 32 {
				return nil, BackendLocalDev, errors.New("LOCALDEV_ENVELOPE_KEY must be 32 bytes, base64 encoded (openssl rand -base64 32)")
			}
			opts = append(opts, localdev.WithEnvelopeMasterKey(key))
		} else {
			slog.Warn("keymanager: LOCALDEV_ENVELOPE_KEY is not set: TOTP secrets enrolled now will be unreadable after a restart")
		}
		return localdev.New(os.Getenv("APP_ENV"), opts...), BackendLocalDev, nil
	default:
		return nil, backend, fmt.Errorf("unknown backend %q: use vault, ovhkms or local_dev", backend)
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
		// master accepts only passkeys and security keys: its accounts cannot sign in.
		slog.Warn("passkeys: disabled (set WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGINS to enable them): the accounts of the master realm cannot sign in")
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
		logging.Fatal("passkeys: invalid settings", "error", err)
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
			logging.Fatal("PUBLIC_URL is required when APP_ENV=production")
		}
		publicURL = "http://localhost:" + IdPPort()
		slog.Warn("PUBLIC_URL is not set, using " + publicURL + " (development only)")
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
		logging.Fatal("client ip: invalid settings", "error", err)
	}
	slog.Info(res.String())
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
			logging.Fatal("PASSWORD_HASH_CONCURRENCY must be a whole number of at least 1", "value", v)
		}
		n = parsed
	}
	service.SetPasswordHashConcurrency(n)
	slog.Info("passwords: Argon2id", "max_hashes_at_a_time", n, "ram_mib", n*service.PasswordHashMemoryMiB)
}

func GeoIP() service.GeoIPResolver {
	path := os.Getenv("GEOIP_DB_PATH")
	if path == "" {
		slog.Info("geoip: GEOIP_DB_PATH is not set: no \"new country\" signal on sign-ins")
		return nil
	}
	r, err := geoip.Open(path)
	if err != nil {
		logging.Fatal("geoip: cannot open the database", "error", err)
	}
	slog.Info("geoip: " + r.Description())
	return r
}

func EmailSender(templates *notify.Templates) notify.EmailSender {
	sender, err := SMTPSender(templates)
	if err != nil {
		logging.Fatal("mail: invalid SMTP settings", "error", err)
	}
	if sender == nil {
		if os.Getenv("APP_ENV") == "development" {
			slog.Warn("mail: SMTP_HOST is not set: e-mails are printed in this log instead (development only)")
			return &notify.LogEmailSender{Templates: templates, Logger: nil}
		}
		slog.Warn("mail: SMTP_HOST is not set: no e-mail is sent, \"forgot password\" is disabled")
		return nil
	}
	cfg := sender.Config()
	slog.Info("mail: SMTP", "host", cfg.Host, "port", cfg.Port, "security", cfg.Security, "from", cfg.From)
	return sender
}

// SMTPSender reads the SMTP_* settings of EmailSender: nil when SMTP_HOST
// is not set.
func SMTPSender(templates *notify.Templates) (*notify.SMTPEmailSender, error) {
	appEnv := os.Getenv("APP_ENV")
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return nil, nil
	}

	port := 0
	if p := os.Getenv("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("SMTP_PORT %q is not a number", p)
		}
		port = n
	}
	from := Unquote(os.Getenv("SMTP_FROM"))
	if from == "" {
		if appEnv == "production" {
			return nil, errors.New("SMTP_FROM is required when APP_ENV=production")
		}
		from = "Oh-My-SSO <no-reply@localhost>"
	}
	security := notify.Security(strings.ToLower(os.Getenv("SMTP_SECURITY")))
	if security == notify.SecurityNone && appEnv == "production" && !isLoopbackHost(host) {
		return nil, errors.New("SMTP_SECURITY=none sends passwords and reset links in clear: refused in production (except to localhost)")
	}

	return notify.NewSMTPEmailSender(notify.SMTPConfig{
		Host:     host,
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		Security: security,
		From:     from,
		HeloName: os.Getenv("SMTP_HELO_NAME"),
	}, templates)
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
	t, err := notify.LoadTemplates(Languages())
	if err != nil {
		logging.Fatal("mail: cannot load the templates", "error", err) // embedded files: only a broken build gets here
	}
	return t
}
