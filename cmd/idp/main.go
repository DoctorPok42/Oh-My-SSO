package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"sso.internal/sso/ent"
	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/keymanager/ovhkms"
	"sso.internal/sso/internal/keymanager/vault"
	"sso.internal/sso/internal/oidcstore"
	"sso.internal/sso/internal/passkey"
	"sso.internal/sso/internal/storage/entstore"
)

// buildKeyManager returns the KeyManager and the backend name stored on each
// SigningKey it creates (SigningKey.kms_backend).
func buildKeyManager() (keymanager.KeyManager, string) {
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
	case "local_dev", "":
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
		return localdev.New(os.Getenv("APP_ENV"), opts...), backendLocalDev
	default:
		log.Fatalf("keymanager: unknown backend %q", backend)
		return nil, ""
	}
}

// buildPasskeys returns the WebAuthn engine, or nil (passkeys disabled) when
// WEBAUTHN_RP_ID is not set.
//
//	WEBAUTHN_RP_ID=localhost
//	WEBAUTHN_RP_ORIGINS=http://localhost:8080          (comma separated)
//	WEBAUTHN_RP_DISPLAY_NAME=Oh-My-SSO                  (optional)
func buildPasskeys() service.PasskeyProvider {
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

func buildEntClient() *ent.Client {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	drv := entsql.OpenDB(dialect.Postgres, db)
	return ent.NewClient(ent.Driver(drv))
}

// buildOIDC returns the OpenID Connect adapter.
//
//	PUBLIC_URL=https://sso.example.com   external URL of this server; the issuer
//	                                     of a realm is PUBLIC_URL/r/<realm>
//
// Without PUBLIC_URL (development only) the server uses http://localhost:<PORT>.
// http:// is refused when APP_ENV=production: OIDC requires https issuers.
func buildOIDC(port string, idp core.IdentityCore, store oidcstore.Store, passkeys bool) *oidcadapter.Adapter {
	appEnv := os.Getenv("APP_ENV")
	publicURL := os.Getenv("PUBLIC_URL")
	if publicURL == "" {
		if appEnv == "production" {
			log.Fatalf("oidc: PUBLIC_URL is required when APP_ENV=production")
		}
		publicURL = "http://localhost:" + port
		log.Printf("oidc: PUBLIC_URL is not set, using %s (development only)", publicURL)
	}
	a, err := oidcadapter.New(oidcadapter.Config{
		PublicURL:         publicURL,
		AllowInsecureHTTP: appEnv != "production",
		SessionCookieName: httpserver.SessionCookieName,
		PasskeysEnabled:   passkeys,
		DevPages:          appEnv == "development",
	}, idp, store)
	if err != nil {
		log.Fatalf("oidc: %v", err)
	}
	log.Printf("oidc: issuer of realm <name> is %s/r/<name>", strings.TrimRight(publicURL, "/"))
	return a
}

const backendLocalDev = "local_dev"

// main dispatches between the two modes of the binary:
//
//	idp            (or "idp serve") start the HTTP server
//	idp keys ...   manage signing keys from the command line (see keys.go)
//	idp mfa ...    manage second factors and MFA policies (see mfa.go)
//	idp oidc ...   manage OIDC clients (see oidc.go)
//	idp dev seed   demo realm, user and OIDC client (development only, see dev.go)
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "keys":
			os.Exit(runKeysCommand(os.Args[2:]))
		case "mfa":
			os.Exit(runMFACommand(os.Args[2:]))
		case "oidc":
			os.Exit(runOIDCCommand(os.Args[2:]))
		case "dev":
			os.Exit(runDevCommand(os.Args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n\nusage:\n  idp [serve]\n  idp keys <rotate|retire|list> [flags]\n  idp mfa <list|reset|policy> [flags]\n  idp oidc clients <create|list|rotate-secret> [flags]\n  idp dev seed [flags]\n", os.Args[1])
			os.Exit(2)
		}
	}
	serve()
}

func serve() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client := buildEntClient()
	defer client.Close()

	keyManager, kmsBackend := buildKeyManager()

	timeouts := service.NoActiveTimeouts{}

	userRepo := entstore.NewUserRepository(client)
	clientRepo := entstore.NewClientRepository(client)
	realmRepo := entstore.NewRealmRepository(client)
	tokenRepo := entstore.NewTokenRepository(client)
	signingKeyRepo := entstore.NewSigningKeyRepository(client)
	settingsRepo := entstore.NewInstanceSettingsRepository(client)

	authService := service.NewAuthService(
		userRepo,
		entstore.NewLoginAttemptRepository(client),
		service.WithTimeoutChecker(timeouts),
	)

	valkeyClient, err := valkeycache.New(os.Getenv("VALKEY_ADDR"))
	if err != nil {
		log.Fatalf("valkey: %v", err)
	}

	sessionService := service.NewSessionService(
		entstore.NewSessionRepository(client),
		settingsRepo,
		tokenRepo,
		valkeycache.NewSessionCache(valkeyClient),
	)

	rbacService := service.NewRBACService(
		entstore.NewAccessRepository(client),
		entstore.NewAuditLogRepository(client),
	)

	keyRotation := service.NewKeyRotationService(
		signingKeyRepo,
		entstore.NewKeyRotationLogRepository(client),
		settingsRepo,
		keyManager,
		kmsBackend,
	)

	// --- MFA (Step 9) ---
	encrypter, ok := keyManager.(keymanager.Encrypter)
	if !ok {
		log.Fatalf("keymanager: backend %q cannot encrypt (needed for TOTP secrets)", kmsBackend)
	}
	auditRepo := entstore.NewAuditLogRepository(client)
	mfaPolicy := service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: settingsRepo,
		Clients:  clientRepo,
		Roles:    entstore.NewRoleRepository(client),
		Policies: entstore.NewMfaPolicyRepository(client),
		Access:   entstore.NewAccessRepository(client),
		Audit:    auditRepo,
	})
	mfaService := service.NewMFAService(service.MFADeps{
		Users:         userRepo,
		Methods:       entstore.NewMfaMethodRepository(client),
		BackupCodes:   entstore.NewMfaBackupCodeRepository(client),
		Sessions:      sessionService,
		Policy:        mfaPolicy,
		Envelope:      service.NewEnvelopeService(signingKeyRepo, encrypter, kmsBackend),
		Store:         valkeycache.NewMFAStore(valkeyClient),
		Limiter:       valkeycache.NewRateLimiter(valkeyClient),
		LoginAttempts: entstore.NewLoginAttemptRepository(client),
		Audit:         auditRepo,
		Realms:        realmRepo,
		Clients:       clientRepo,
		Passkeys:      buildPasskeys(),
		IssuerName:    os.Getenv("MFA_TOTP_ISSUER"),
	})

	identityCore := service.NewIdentityCore(service.IdentityCoreDeps{
		Auth:        authService,
		Sessions:    sessionService,
		RBAC:        rbacService,
		Users:       userRepo,
		Clients:     clientRepo,
		Realms:      realmRepo,
		Tokens:      tokenRepo,
		SigningKeys: signingKeyRepo,
		KeyManager:  keyManager,
		Timeouts:    timeouts,
		MFA:         mfaService,
		Audit:       auditRepo,
	})

	// --- OpenID Connect (Step 10) ---
	oidcProvider := buildOIDC(port, identityCore, valkeycache.NewOIDCStore(valkeyClient), mfaService.PasskeysEnabled())

	srv := httpserver.New(
		authService,
		sessionService,
		rbacService,
		realmRepo,
		clientRepo,
		valkeycache.NewRateLimiter(valkeyClient),
		httpserver.WithJWKS(identityCore),
		httpserver.WithSigningKeyAdmin(keyRotation),
		httpserver.WithMFA(mfaService),
		httpserver.WithDevPages(os.Getenv("APP_ENV") == "development"),
		httpserver.WithOIDC(oidcProvider),
	)

	log.Printf("Starting server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, srv.Router()))
}
