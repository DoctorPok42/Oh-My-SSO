package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	entclientscope "sso.internal/sso/ent/clientscope"
	entrole "sso.internal/sso/ent/role"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// "idp dev seed" prepares a database to try the OIDC and SAML flows by
// hand, until the admin panel (Step 14) can create realms and users.
// Development only.
//
//	idp dev seed [--realm demo] [--user alice] [--password ...] [--redirect-uri http://localhost:9000/callback]
//
// It is idempotent: what exists is kept (an existing user keeps its
// password), so it can be run again. Every run gives the demo client a new
// secret, because a secret is only shown once.

const devUsage = `usage:
  idp dev seed [--realm demo] [--user alice] [--password <text>] [--redirect-uri <uri>]
               (APP_ENV=development only)
`

const (
	demoClientID = "demo"
	demoRole     = "employees"
	// demoSAMLScope (Step 11) turns the user's profile into the usual SAML
	// attributes. SAML clients list it with --scope.
	demoSAMLScope = "saml_profile"
)

// demoSAMLMappers: uid, mail, givenName, sn, plus the user's groups and
// roles as multi-valued attributes. Basic attribute names, the simplest for
// a service provider to read.
var demoSAMLMappers = []map[string]interface{}{
	{"source_attribute": "username", "claim_name": "uid", "token_location": "saml_attribute"},
	{"source_attribute": "email", "claim_name": "mail", "token_location": "saml_attribute"},
	{"source_attribute": "profile.given_name", "claim_name": "givenName", "token_location": "saml_attribute"},
	{"source_attribute": "profile.family_name", "claim_name": "sn", "token_location": "saml_attribute"},
	{"source_attribute": "groups", "claim_name": "groups", "token_location": "saml_attribute"},
	{"source_attribute": "roles", "claim_name": "roles", "token_location": "saml_attribute"},
}

func runDevCommand(args []string) int {
	if len(args) == 0 || args[0] != "seed" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			fmt.Fprint(os.Stdout, devUsage)
			return 0
		}
		fmt.Fprint(os.Stderr, devUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := devSeed(ctx, args[1:], os.Stdout)
	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, devUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

func devSeed(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dev seed", flag.ContinueOnError)
	realmName := fs.String("realm", "demo", "realm to create or reuse")
	username := fs.String("user", "alice", "user to create or reuse")
	password := fs.String("password", "", "password of a NEW user (default: a random one, printed once)")
	redirectURI := fs.String("redirect-uri", "http://localhost:9000/callback", "redirect URI of the demo client (cmd/oidc-demo)")
	postLogout := fs.String("post-logout-uri", "http://localhost:9000/", "post-logout redirect URI of the demo client")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Getenv("APP_ENV") != "development" {
		return errors.New("idp dev seed only runs with APP_ENV=development")
	}
	if os.Getenv("DATABASE_URL") == "" {
		return errors.New("DATABASE_URL is not set (hint: `make` targets load .env, or export it)")
	}

	client := buildEntClient()
	defer client.Close()
	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	roles := entstore.NewRoleRepository(client)
	access := entstore.NewAccessRepository(client)
	rbac := service.NewRBACService(access, entstore.NewAuditLogRepository(client))

	// 1. The realm.
	realm, err := realms.GetByName(ctx, *realmName)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		realm, err = realms.Create(ctx, repository.CreateRealmParams{Name: *realmName, DisplayName: *realmName})
		if err != nil {
			return fmt.Errorf("create realm: %w", err)
		}
		fmt.Fprintf(out, "realm %q: created\n", realm.Name)
	case err != nil:
		return fmt.Errorf("load realm: %w", err)
	default:
		fmt.Fprintf(out, "realm %q: exists\n", realm.Name)
	}

	// 2. Its signing key. With local_dev the private key would live in this
	// process's memory and die with it: the server could not use it.
	km, backend := buildKeyManager()
	rotation := service.NewKeyRotationService(entstore.NewSigningKeyRepository(client),
		entstore.NewKeyRotationLogRepository(client), entstore.NewInstanceSettingsRepository(client), km, backend)
	keys, err := rotation.List(ctx, realm.ID)
	if err != nil {
		return fmt.Errorf("list signing keys: %w", err)
	}
	hasKey := slices.ContainsFunc(keys, func(k *domain.SigningKey) bool {
		return k.Status == domain.SigningKeyActive && k.Purpose == domain.SigningKeyPurposeJWT
	})
	switch {
	case hasKey:
		fmt.Fprintln(out, "signing key: exists")
	case backend == backendLocalDev:
		fmt.Fprintln(out, "signing key: NOT created: KEYMANAGER_BACKEND=local_dev keeps keys in the memory of one process.")
		fmt.Fprintln(out, "             Use KEYMANAGER_BACKEND=vault (make dev starts Vault), then run this again.")
	default:
		res, err := rotation.Rotate(ctx, service.RotateInput{RealmID: realm.ID, TriggeredBy: cliActor(), Reason: "idp dev seed"})
		if err != nil {
			return fmt.Errorf("create signing key: %w", err)
		}
		fmt.Fprintf(out, "signing key: created (%s)\n", res.NewKey.Kid)
	}

	// 3. A role: OIDC clients are deny by default, only its members may log in.
	role, err := roles.GetByRealmAndName(ctx, realm.ID, demoRole)
	if errors.Is(err, repository.ErrNotFound) {
		role, err = roles.Create(ctx, repository.CreateRoleParams{RealmID: realm.ID, Name: demoRole,
			Description: "members may use the demo OIDC client"})
	}
	if err != nil {
		return fmt.Errorf("role %q: %w", demoRole, err)
	}

	// 4. The user, member of the role.
	user, err := users.GetByRealmAndUsername(ctx, realm.ID, *username)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		pw := *password
		if pw == "" {
			pw = rand.Text()[:16]
		}
		// Step 12: the realm's password policy applies here too.
		policy := service.NewPasswordPolicyService(entstore.NewInstanceSettingsRepository(client))
		if err := policy.Validate(ctx, realm.ID, pw, &domain.User{Username: *username, Email: *username + "@example.test"}); err != nil {
			return fmt.Errorf("--password: %w", err)
		}
		hash, err := service.HashPassword(pw)
		if err != nil {
			return err
		}
		user, err = users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: *username,
			Email: *username + "@example.test", PasswordHash: hash, Status: domain.UserActive})
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		err = client.User.UpdateOneID(user.ID).
			SetProfile(map[string]interface{}{"given_name": *username, "family_name": "Demo", "email_verified": true}).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("set profile: %w", err)
		}
		fmt.Fprintf(out, "user %q: created, password: %s\n", user.Username, pw)
	case err != nil:
		return fmt.Errorf("load user: %w", err)
	default:
		fmt.Fprintf(out, "user %q: exists (password unchanged)\n", user.Username)
	}
	_, roleNames, err := rbac.UserAccessNames(ctx, user.ID)
	if err != nil {
		return err
	}
	if !slices.Contains(roleNames, demoRole) {
		if err := client.User.UpdateOneID(user.ID).AddRoleIDs(role.ID).Exec(ctx); err != nil {
			return fmt.Errorf("assign role: %w", err)
		}
	}
	fmt.Fprintf(out, "role %q: %s is a member\n", demoRole, user.Username)

	// 5. The demo OIDC client (confidential, like cmd/oidc-demo).
	oidcClients := service.NewOIDCClientService(entstore.NewClientRepository(client),
		entstore.NewClientScopeRepository(client), roles, entstore.NewGroupRepository(client))
	var secret string
	_, err = entstore.NewClientRepository(client).GetByRealmAndClientID(ctx, realm.ID, demoClientID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		_, secret, err = oidcClients.Create(ctx, service.OIDCClientInput{
			RealmID: realm.ID, Name: "OIDC demo", ClientID: demoClientID,
			RedirectURIs: []string{*redirectURI}, PostLogoutRedirectURIs: []string{*postLogout},
			Scopes: []string{"profile", "email", "offline_access"}, AllowRoles: []string{demoRole},
			GrantedBy: cliActor(),
		})
		if err != nil {
			return fmt.Errorf("create client %q: %w", demoClientID, err)
		}
		fmt.Fprintf(out, "client %q: created\n", demoClientID)
	case err != nil:
		return fmt.Errorf("load client %q: %w", demoClientID, err)
	default:
		if secret, err = oidcClients.RotateSecret(ctx, realm.ID, demoClientID); err != nil {
			return fmt.Errorf("rotate secret of %q: %w", demoClientID, err)
		}
		fmt.Fprintf(out, "client %q: exists, new secret generated (the previous one stops working)\n", demoClientID)
	}

	// 6. SAML (Step 11): the realm's SAML signing key, and a ClientScope
	// producing the attributes, granted to the demo role.
	hasSAMLKey := slices.ContainsFunc(keys, func(k *domain.SigningKey) bool {
		return k.Purpose == domain.SigningKeyPurposeSAMLSigning &&
			(k.Status == domain.SigningKeyActive || k.Status == domain.SigningKeyPending)
	})
	switch {
	case hasSAMLKey:
		fmt.Fprintln(out, "SAML signing key: exists")
	case backend == backendLocalDev:
		fmt.Fprintln(out, "SAML signing key: NOT created (local_dev, see above). Or create it through the running server:")
		fmt.Fprintf(out, "             POST /r/%s/admin/signing-keys/rotate {\"purpose\":\"saml_signing\"}\n", realm.Name)
	default:
		res, err := rotation.Rotate(ctx, service.RotateInput{RealmID: realm.ID, Purpose: domain.SigningKeyPurposeSAMLSigning,
			TriggeredBy: cliActor(), Reason: "idp dev seed"})
		if err != nil {
			return fmt.Errorf("create SAML signing key: %w", err)
		}
		fmt.Fprintf(out, "SAML signing key: created (%s)\n", res.NewKey.Kid)
	}
	scopes := entstore.NewClientScopeRepository(client)
	samlScope, err := scopes.GetByRealmAndName(ctx, realm.ID, demoSAMLScope)
	if errors.Is(err, repository.ErrNotFound) {
		samlScope, err = scopes.Create(ctx, repository.CreateClientScopeParams{RealmID: realm.ID, Name: demoSAMLScope,
			Description: "usual SAML attributes (uid, mail, givenName, sn, groups, roles)"})
		if err == nil {
			protocol := domain.ClientScopeProtocolSAML2
			samlScope, err = scopes.Update(ctx, samlScope.ID, repository.UpdateClientScopeParams{
				Protocol: &protocol, ClaimMappers: demoSAMLMappers,
			})
		}
		if err == nil {
			fmt.Fprintf(out, "client scope %q: created\n", demoSAMLScope)
		}
	} else if err == nil {
		fmt.Fprintf(out, "client scope %q: exists\n", demoSAMLScope)
	}
	if err != nil {
		return fmt.Errorf("client scope %q: %w", demoSAMLScope, err)
	}
	granted, err := client.Role.Query().Where(entrole.ID(role.ID)).QueryClientScopes().
		Where(entclientscope.ID(samlScope.ID)).Exist(ctx)
	if err != nil {
		return fmt.Errorf("client scope %q: %w", demoSAMLScope, err)
	}
	if !granted {
		if err := client.Role.UpdateOneID(role.ID).AddClientScopeIDs(samlScope.ID).Exec(ctx); err != nil {
			return fmt.Errorf("grant client scope %q: %w", demoSAMLScope, err)
		}
	}
	fmt.Fprintf(out, "client scope %q: granted to role %q\n", demoSAMLScope, demoRole)

	fmt.Fprintf(out, "\nSAML IdP metadata (give it to a service provider): %s/r/%s/saml/metadata\n", devPublicURL(), realm.Name)
	fmt.Fprintf(out, "Register a service provider: idp saml clients create --realm %s --metadata-url <its metadata URL> --allow-role %s --scope %s\n",
		realm.Name, demoRole, demoSAMLScope)

	// Step 13: the demo client does not ask for consent; one command shows
	// the consent screen.
	fmt.Fprintf(out, "\nConsent screen: make consent-on realm=%s client=%s (and consent-off to stop)\n", realm.Name, demoClientID)

	fmt.Fprintf(out, "\nFor cmd/oidc-demo (put these in .env, then `make oidc-demo`):\n")
	fmt.Fprintf(out, "  DEMO_ISSUER=%s/r/%s\n", devPublicURL(), realm.Name)
	fmt.Fprintf(out, "  DEMO_CLIENT_ID=%s\n", demoClientID)
	fmt.Fprintf(out, "  DEMO_CLIENT_SECRET=%s\n", secret)
	return nil
}

// devPublicURL: what the server uses as PUBLIC_URL (see buildPublicURL).
func devPublicURL() string {
	if u := os.Getenv("PUBLIC_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return "http://localhost:" + port
}
