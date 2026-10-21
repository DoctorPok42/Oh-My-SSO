package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// "idp consents ..." (Step 13): the consent screen setting of a client, and
// the consents users gave. Same service as the admin and user panels of
// Step 14 will use.
//
//	idp consents set-client --realm demo --client partner --required=true
//	idp consents list       --realm demo --user alice
//	idp consents revoke     --realm demo --user alice --client partner --reason "asked by the user"
//
// Revoking also revokes the tokens the client holds for the user: its next
// refresh fails, and the next sign-in shows the consent screen again.

const consentsUsage = `usage:
  idp consents set-client --realm <name> --client <client_id|entity_id> --required=true|false
  idp consents list       --realm <name> --user <username|email>
  idp consents revoke     --realm <name> --user <username|email> --client <client_id|entity_id> [--reason <text>]
`

func runConsentsCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, consentsUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch args[0] {
	case "set-client":
		err = consentsSetClient(ctx, args[1:], os.Stdout)
	case "list":
		err = consentsList(ctx, args[1:], os.Stdout)
	case "revoke":
		err = consentsRevoke(ctx, args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, consentsUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown consents command %q", args[0])}
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, consentsUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

// consentService builds the service on the database. No Valkey: revoking a
// consent revokes tokens in PostgreSQL, where /userinfo, /introspect and
// the refresh grant look them up.
func (e *mfaEnv) consentService() *service.ConsentService {
	return service.NewConsentService(service.ConsentDeps{
		Consents: entstore.NewConsentRepository(e.client),
		Clients:  entstore.NewClientRepository(e.client),
		Tokens:   entstore.NewTokenRepository(e.client),
		Audit:    entstore.NewAuditLogRepository(e.client),
	})
}

func consentsSetClient(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("consents set-client", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	clientArg := fs.String("client", "", "client_id (OIDC), entity_id (SAML) or internal id (required)")
	required := fs.String("required", "", "true: users approve the client on a consent screen; false: never asked (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientArg == "" || *required == "" {
		return usageError{"--client and --required are required"}
	}
	on, err := strconv.ParseBool(*required)
	if err != nil {
		return usageError{"--required must be true or false"}
	}
	env, err := openMFAEnv(ctx, *realmName) // same needs: database + realm
	if err != nil {
		return err
	}
	defer env.close()

	client, err := findClient(ctx, entstore.NewClientRepository(env.client), env.realm.ID, *clientArg)
	if err != nil {
		return err
	}
	c, err := env.consentService().SetClientRequirement(ctx, service.SetClientConsentInput{
		RealmID: env.realm.ID, ClientRef: client.ID, Required: on,
		Actor: service.PolicyActor{TriggeredBy: cliActor()},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "client %s (%s): consent %s\n", c.Name, clientIdentifier(c), consentLabel(c.RequireConsent))
	if !c.RequireConsent {
		fmt.Fprintln(out, "  the consents already given are kept: turning it on again reuses them")
	}
	return nil
}

func consentsList(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("consents list", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	userArg := fs.String("user", "", "username or email (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()
	user, err := env.findUser(ctx, *userArg)
	if err != nil {
		return err
	}
	list, err := env.consentService().List(ctx, env.realm.ID, user.ID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintf(out, "%s has not approved any application\n", user.Username)
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tNAME\tPROTOCOL\tSTATUS\tSCOPES\tGRANTED\tCHANGED")
	for _, v := range list {
		id, name, protocol := "(deleted)", "-", "-"
		if v.Client != nil {
			id, name, protocol = clientIdentifier(v.Client), orDash(v.Client.Name), string(v.Client.Protocol)
		}
		scopes := strings.Join(v.Consent.Scopes, " ")
		if scopes == "" {
			scopes = "(identity only)"
		}
		status := string(v.Consent.Status)
		if v.Consent.Status == domain.ConsentRevoked && !v.Consent.RevokedAt.IsZero() {
			status += " " + v.Consent.RevokedAt.UTC().Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, name, protocol, status, scopes,
			v.Consent.GrantedAt.UTC().Format("2006-01-02 15:04"), v.Consent.UpdatedAt.UTC().Format("2006-01-02 15:04"))
	}
	return tw.Flush()
}

func consentsRevoke(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("consents revoke", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	userArg := fs.String("user", "", "username or email (required)")
	clientArg := fs.String("client", "", "client_id (OIDC), entity_id (SAML) or internal id (required)")
	reason := fs.String("reason", "", "why, for the audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientArg == "" {
		return usageError{"--client is required"}
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()
	user, err := env.findUser(ctx, *userArg)
	if err != nil {
		return err
	}
	client, err := findClient(ctx, entstore.NewClientRepository(env.client), env.realm.ID, *clientArg)
	if err != nil {
		return err
	}
	res, err := env.consentService().Revoke(ctx, service.RevokeConsentInput{
		RealmID: env.realm.ID, UserID: user.ID, ClientRef: client.ID,
		Actor: service.PolicyActor{TriggeredBy: cliActor()}, Reason: *reason,
	})
	if errors.Is(err, service.ErrConsentNotFound) {
		return fmt.Errorf("%s never approved %s", user.Username, clientIdentifier(client))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "consent of %s for %s: revoked (%d active token(s) revoked)\n", user.Username, clientIdentifier(client), res.TokensRevoked)
	if client.RequireConsent {
		fmt.Fprintln(out, "  the next sign-in to this application shows the consent screen again")
	}
	return nil
}

func consentLabel(required bool) string {
	if required {
		return "required"
	}
	return "off"
}
