package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/keymanager/ovhkms"
	"sso.internal/sso/internal/keymanager/vault"
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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	_ = buildKeyManager()

	log.Printf("Starting server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
