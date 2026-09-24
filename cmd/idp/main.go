package main

import (
	"database/sql"
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

func buildKeyManager() keymanager.KeyManager {
	switch backend := os.Getenv("KEYMANAGER_BACKEND"); backend {
	case "vault":
		km, err := vault.New(vault.Config{
			Address: os.Getenv("VAULT_ADDR"),
			Token:   os.Getenv("VAULT_TOKEN"),
		})
		if err != nil {
			log.Fatalf("keymanager: %v", err)
		}
		return km
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
		return km
	case "local_dev", "":
		return localdev.New(os.Getenv("APP_ENV"))
	default:
		log.Fatalf("keymanager: unknown backend %q", backend)
		return nil
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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client := buildEntClient()
	defer client.Close()

	_ = buildKeyManager()

	authService := service.NewAuthService(
		entstore.NewUserRepository(client),
		entstore.NewLoginAttemptRepository(client),
	)

	valkeyClient, err := valkeycache.New(os.Getenv("VALKEY_ADDR"))
	if err != nil {
		log.Fatalf("valkey: %v", err)
	}

	sessionService := service.NewSessionService(
		entstore.NewSessionRepository(client),
		entstore.NewInstanceSettingsRepository(client),
		valkeycache.NewSessionCache(valkeyClient),
	)

	srv := httpserver.New(
		authService,
		sessionService,
		entstore.NewRealmRepository(client),
		valkeycache.NewRateLimiter(valkeyClient),
	)

	log.Printf("Starting server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, srv.Router()))
}
