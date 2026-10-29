package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sso.internal/sso/ent"
	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	samladapter "sso.internal/sso/internal/adapters/saml"
	"sso.internal/sso/internal/app"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/oidcstore"
)


func buildKeyManager() (keymanager.KeyManager, string) { return app.KeyManager() }

func buildEntClient() *ent.Client { return app.EntClient() }

func buildOIDC(publicURL string, idp core.IdentityCore, store oidcstore.Store, passkeys, passwordReset bool) *oidcadapter.Adapter {
	appEnv := os.Getenv("APP_ENV")
	a, err := oidcadapter.New(oidcadapter.Config{
		PublicURL:         publicURL,
		AllowInsecureHTTP: appEnv != "production",
		SessionCookieName: httpserver.SessionCookieName,
		DeviceCookieName:  httpserver.DeviceCookieName,
		PasskeysEnabled:   passkeys,
		DevPages:          appEnv == "development",
		PasswordReset:     passwordReset,
	}, idp, store)
	if err != nil {
		log.Fatalf("oidc: %v", err)
	}
	log.Printf("oidc: issuer of realm <name> is %s/r/<name>", strings.TrimRight(publicURL, "/"))
	return a
}

func buildSAML(publicURL string, idp core.IdentityCore, store oidcstore.Store, passkeys, passwordReset bool) *samladapter.Adapter {
	appEnv := os.Getenv("APP_ENV")
	a, err := samladapter.New(samladapter.Config{
		PublicURL:         publicURL,
		AllowInsecureHTTP: appEnv != "production",
		SessionCookieName: httpserver.SessionCookieName,
		DeviceCookieName:  httpserver.DeviceCookieName,
		PasskeysEnabled:   passkeys,
		DevPages:          appEnv == "development",
		PasswordReset:     passwordReset,
	}, idp, store)
	if err != nil {
		log.Fatalf("saml: %v", err)
	}
	log.Printf("saml: IdP metadata of realm <name> is %s/r/<name>/saml/metadata", strings.TrimRight(publicURL, "/"))
	return a
}

const backendLocalDev = app.BackendLocalDev

// main dispatches between the two modes of the binary:
//
//	idp            (or "idp serve") start the HTTP server
//	idp keys ...   manage signing keys from the command line (see keys.go)
//	idp mfa ...    manage second factors and MFA policies (see mfa.go)
//	idp oidc ...   manage OIDC clients (see oidc.go)
//	idp saml ...   manage SAML clients (see saml.go)
//	idp consents . consent screen setting, users' consents (see consents.go)
//	idp users ...  account lockout: status, unlock (see users.go)
//	idp timeouts . suspend a user, a group or a client for a while (see timeouts.go)
//	idp settings . realm settings: e-mails, lockout, passwords (see settings.go)
//	idp mail test  send a test e-mail with the SMTP_* settings (see mail.go)
//	idp dev seed   demo realm, user and OIDC client (development only, see dev.go)
func main() {
	if err := guardMasterRealm(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		case "keys":
			os.Exit(runKeysCommand(os.Args[2:]))
		case "mfa":
			os.Exit(runMFACommand(os.Args[2:]))
		case "oidc":
			os.Exit(runOIDCCommand(os.Args[2:]))
		case "saml":
			os.Exit(runSAMLCommand(os.Args[2:]))
		case "consents":
			os.Exit(runConsentsCommand(os.Args[2:]))
		case "users":
			os.Exit(runUsersCommand(os.Args[2:]))
		case "timeouts":
			os.Exit(runTimeoutsCommand(os.Args[2:]))
		case "settings":
			os.Exit(runSettingsCommand(os.Args[2:]))
		case "mail":
			os.Exit(runMailCommand(os.Args[2:]))
		case "dev":
			os.Exit(runDevCommand(os.Args[2:]))
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n\nusage:\n  idp [serve]\n  idp keys <rotate|activate|retire|list> [flags]\n  idp mfa <list|reset|policy> [flags]\n  idp oidc clients <create|list|rotate-secret> [flags]\n  idp saml clients <create|list|add-cert|remove-cert> [flags]\n  idp consents <set-client|list|revoke> [flags]\n  idp users <status|unlock> [flags]\n  idp timeouts <list|create|update|lift> [flags]\n  idp settings <show|set> [flags]\n  idp mail test --to <address>\n  idp dev seed [flags]\n", os.Args[1])
			os.Exit(2)
		}
	}
	serve()
}

func serve() {
	port := app.IdPPort()

	c := app.BuildCore()
	defer c.Close()
	// Scheduled timeouts: their targets are signed out when they start.
	c.StartTimeoutEnforcer()

	flowStore := valkeycache.NewOIDCStore(c.Valkey)
	oidcProvider := buildOIDC(c.PublicURL, c.IdentityCore, flowStore, c.MFA.PasskeysEnabled(), c.EmailEnabled())
	samlProvider := buildSAML(c.PublicURL, c.IdentityCore, flowStore, c.MFA.PasskeysEnabled(), c.EmailEnabled())

	opts := []httpserver.Option{
		httpserver.WithJWKS(c.IdentityCore),
		httpserver.WithMFA(c.MFA),
		httpserver.WithDevPages(os.Getenv("APP_ENV") == "development"),
		httpserver.WithOIDC(oidcProvider),
		httpserver.WithSAML(samlProvider),
		httpserver.WithPasswordReset(c.PasswordReset),
		httpserver.WithForgotPassword(c.EmailEnabled()),
		httpserver.WithKnownAccounts(c.KnownAccounts),
	}
	srv := httpserver.New(
		c.Auth,
		c.Sessions,
		c.RBAC,
		c.Realms,
		c.Clients,
		c.RateLimiter,
		opts...,
	)

	httpSrv := &http.Server{Addr: ":" + port, Handler: srv.Router(), ReadHeaderTimeout: 10 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	log.Printf("Starting server on port %s...", port)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
