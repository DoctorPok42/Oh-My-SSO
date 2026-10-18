package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// "idp oidc clients ..." manages OIDC clients until the admin panel exists
// (Step 14). It calls the same service the admin API and `idp config apply`
// will use, so the validation rules are the same everywhere.
//
//	idp oidc clients list          --realm demo
//	idp oidc clients create        --realm demo --client-id payroll --redirect-uri https://payroll.example.com/callback \
//	                               --scope profile,email,offline_access --allow-role employees
//	idp oidc clients create        --realm demo --client-id spa --public --redirect-uri http://localhost:5173/callback
//	idp oidc clients rotate-secret --realm demo --client-id payroll
//
// Like the server, it reads DATABASE_URL from the environment.

const oidcUsage = `usage:
  idp oidc clients list          --realm <name>
  idp oidc clients create        --realm <name> --client-id <id> --redirect-uri <uri> [--redirect-uri <uri>...]
                                 [--name <text>] [--public] [--scope <a,b>] [--post-logout-uri <uri>]
                                 [--grant authorization_code,refresh_token] [--auth-method client_secret_basic|client_secret_post]
                                 [--no-pkce] [--allow-role <name>] [--allow-group <name>]
  idp oidc clients rotate-secret --realm <name> --client-id <id>
`

func runOIDCCommand(args []string) int {
	if len(args) < 2 || args[0] != "clients" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			fmt.Fprint(os.Stdout, oidcUsage)
			return 0
		}
		fmt.Fprint(os.Stderr, oidcUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch args[1] {
	case "list":
		err = oidcClientsList(ctx, args[2:], os.Stdout)
	case "create":
		err = oidcClientsCreate(ctx, args[2:], os.Stdout)
	case "rotate-secret":
		err = oidcClientsRotateSecret(ctx, args[2:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, oidcUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown oidc clients command %q", args[1])}
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, oidcUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

// listFlag is a repeatable flag that also accepts comma separated values:
// --scope profile,email --scope groups
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

type oidcEnv struct {
	client  *ent.Client
	realm   *domain.Realm
	clients *service.OIDCClientService
}

func openOIDCEnv(ctx context.Context, realmName string) (*oidcEnv, error) {
	if realmName == "" {
		return nil, usageError{"--realm is required"}
	}
	if os.Getenv("DATABASE_URL") == "" {
		return nil, errors.New("DATABASE_URL is not set (hint: `make` targets load .env, or export it)")
	}
	client := buildEntClient()
	realm, err := entstore.NewRealmRepository(client).GetByName(ctx, realmName)
	if errors.Is(err, repository.ErrNotFound) {
		client.Close()
		return nil, fmt.Errorf("realm %q not found", realmName)
	}
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("load realm %q: %w", realmName, err)
	}
	svc := service.NewOIDCClientService(
		entstore.NewClientRepository(client),
		entstore.NewClientScopeRepository(client),
		entstore.NewRoleRepository(client),
		entstore.NewGroupRepository(client),
	)
	return &oidcEnv{client: client, realm: realm, clients: svc}, nil
}

func oidcClientsList(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oidc clients list", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openOIDCEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()

	list, err := env.clients.List(ctx, env.realm.ID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintf(out, "no OIDC client in realm %s\n", env.realm.Name)
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT_ID\tNAME\tTYPE\tSTATUS\tPKCE\tSCOPES\tREDIRECT URIS")
	for _, c := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\t%s\n", c.ClientID, c.Name, c.ClientType, c.Status,
			c.RequirePKCE || c.ClientType == domain.ClientAppTypePublic,
			strings.Join(c.AllowedScopes, " "), strings.Join(c.RedirectURIs, " "))
	}
	return tw.Flush()
}

func oidcClientsCreate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oidc clients create", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	clientID := fs.String("client-id", "", "public client_id (required)")
	name := fs.String("name", "", "display name shown on the login page (default: the client_id)")
	public := fs.Bool("public", false, "public client (SPA, mobile, CLI): no secret, PKCE mandatory")
	authMethod := fs.String("auth-method", "", "client_secret_basic (default) or client_secret_post")
	noPKCE := fs.Bool("no-pkce", false, "do not require PKCE (confidential clients only, not recommended)")
	var redirects, postLogout, scopes, grants, roles, groups listFlag
	fs.Var(&redirects, "redirect-uri", "allowed redirect URI, exact match (repeatable, required)")
	fs.Var(&postLogout, "post-logout-uri", "allowed post-logout redirect URI (repeatable)")
	fs.Var(&scopes, "scope", "scopes the client may request, besides openid (repeatable or comma separated)")
	fs.Var(&grants, "grant", "grant types (default: authorization_code,refresh_token)")
	fs.Var(&roles, "allow-role", "role whose members may use the client (repeatable)")
	fs.Var(&groups, "allow-group", "group whose members may use the client (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" || len(redirects) == 0 {
		return usageError{"--client-id and at least one --redirect-uri are required"}
	}
	env, err := openOIDCEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()

	app, secret, err := env.clients.Create(ctx, service.OIDCClientInput{
		RealmID:                 env.realm.ID,
		Name:                    *name,
		ClientID:                *clientID,
		Public:                  *public,
		RedirectURIs:            redirects,
		PostLogoutRedirectURIs:  postLogout,
		Scopes:                  scopes,
		GrantTypes:              grants,
		TokenEndpointAuthMethod: *authMethod,
		DisablePKCE:             *noPKCE,
		AllowRoles:              roles,
		AllowGroups:             groups,
		GrantedBy:               cliActor(),
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "created OIDC client %q in realm %s (id %s)\n", app.ClientID, env.realm.Name, app.ID)
	fmt.Fprintf(out, "  type:          %s (token endpoint auth: %s)\n", app.ClientType, app.TokenEndpointAuthMethod)
	fmt.Fprintf(out, "  scopes:        %s\n", strings.Join(app.AllowedScopes, " "))
	fmt.Fprintf(out, "  redirect URIs: %s\n", strings.Join(app.RedirectURIs, " "))
	if len(roles)+len(groups) == 0 {
		fmt.Fprintln(out, "  WARNING: no --allow-role / --allow-group: nobody can log in to this client yet (deny by default).")
	}
	if secret != "" {
		fmt.Fprintf(out, "\nclient_secret: %s\n", secret)
		fmt.Fprintln(out, "Store it now in the application's configuration: it is not stored here and cannot be shown again.")
	}
	fmt.Fprintf(out, "\nDiscovery: <PUBLIC_URL>/r/%s/.well-known/openid-configuration\n", env.realm.Name)
	return nil
}

func oidcClientsRotateSecret(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oidc clients rotate-secret", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	clientID := fs.String("client-id", "", "public client_id (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" {
		return usageError{"--client-id is required"}
	}
	env, err := openOIDCEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()

	secret, err := env.clients.RotateSecret(ctx, env.realm.ID, *clientID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "new client_secret for %q: %s\n", *clientID, secret)
	fmt.Fprintln(out, "The previous secret no longer works. It is shown once.")
	return nil
}
