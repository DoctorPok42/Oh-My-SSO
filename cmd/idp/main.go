package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"sso.internal/sso/ent"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/keymanager/ovhkms"
	"sso.internal/sso/internal/keymanager/vault"
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

func buildEntClient() *ent.Client {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	drv := entsql.OpenDB(dialect.Postgres, db)
	return ent.NewClient(ent.Driver(drv))
}

const backendLocalDev = "local_dev"

// main dispatches between the two modes of the binary:
//
//	idp            (or "idp serve") start the HTTP server
//	idp keys ...   manage signing keys from the command line (see keys.go)
//	idp mfa ...    manage second factors and MFA policies (see mfa.go)
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "keys":
			os.Exit(runKeysCommand(os.Args[2:]))
		case "mfa":
			os.Exit(runMFACommand(os.Args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n\nusage:\n  idp [serve]\n  idp keys <rotate|retire|list> [flags]\n  idp mfa <list|reset|policy> [flags]\n", os.Args[1])
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
	})

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
	)

	log.Printf("Starting server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, srv.Router()))
}
