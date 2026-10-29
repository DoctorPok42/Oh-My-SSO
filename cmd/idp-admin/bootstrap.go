package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/app"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// cliAdmin builds the admin service for the command line: database and
// KeyManager only (no Valkey: bootstrap and recovery need no session cache).
func cliAdmin(notifier service.Notifier) (*service.AdminService, *ent.Client) {
	client := app.EntClient()
	km, backend := app.KeyManager()
	settings := entstore.NewInstanceSettingsRepository(client)
	signingKeys := entstore.NewSigningKeyRepository(client)
	clients := entstore.NewClientRepository(client)
	scopes := entstore.NewClientScopeRepository(client)
	roles := entstore.NewRoleRepository(client)
	groups := entstore.NewGroupRepository(client)
	users := entstore.NewUserRepository(client)
	audit := entstore.NewAuditLogRepository(client)
	return service.NewAdminService(service.AdminDeps{
		Realms: entstore.NewRealmRepository(client), Users: users, Clients: clients, Scopes: scopes,
		Roles: roles, Groups: groups, Permissions: entstore.NewPermissionRepository(client),
		Settings: settings, Audit: audit, Admin: entstore.NewAdminRepository(client),
		KeyRotation: service.NewKeyRotationService(signingKeys, entstore.NewKeyRotationLogRepository(client), settings, km, backend),
		PasswordReset: service.NewPasswordResetService(service.PasswordResetDeps{
			Users: users, Tokens: entstore.NewPasswordResetTokenRepository(client), Settings: settings, Audit: audit,
		}),
		OIDCClients: service.NewOIDCClientService(clients, scopes, roles, groups),
		// Lifting only (recover timeouts): no sign-out, no session cache.
		Timeouts: service.NewTimeoutService(service.TimeoutDeps{
			Timeouts: entstore.NewTimeoutRepository(client), Users: users, Groups: groups, Clients: clients, Audit: audit,
		}),
		Notifier:   notifier,
		PublicURL:  app.DevPublicURL(),
		KMSBackend: backend,
	}), client
}

// cliActor: who runs the command, for the audit log ("cli:alice@admin-1").
func cliActor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return "cli:" + name + "@" + host
}

func runBootstrap(args []string) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail of the first administrator (required)")
	username := fs.String("username", "", "username of the first administrator (default: the part of the e-mail before @)")
	adminURL := fs.String("admin-url", envOr("ADMIN_PANEL_URL", "http://localhost:3000"), "URL of the admin console (Next.js)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *email == "" {
		fmt.Fprintf(os.Stderr, "error: --email is required\n\n%s", usage)
		return 2
	}
	if os.Getenv("DATABASE_URL") == "" {
		fmt.Fprintln(os.Stderr, "error: DATABASE_URL is not set (hint: `make` targets load .env, or export it)")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, client := cliAdmin(service.NopNotifier{})
	defer client.Close()
	res, err := admin.Bootstrap(ctx, service.BootstrapInput{
		AdminEmail: *email, AdminUsername: *username, AdminConsoleURL: *adminURL,
		Actor: cliActor(), Production: os.Getenv("APP_ENV") == "production",
	})
	switch {
	case errors.Is(err, service.ErrAlreadyBootstrapped):
		fmt.Fprintf(os.Stderr, "refused: %v\n", err)
		return 3
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printBootstrap(os.Stdout, res, *adminURL)
	return 0
}

func printBootstrap(out io.Writer, res *service.BootstrapResult, adminURL string) {
	for _, s := range res.Steps {
		fmt.Fprintf(out, "  ✓ %s\n", s)
	}
	if res.SigningKeyWarning != "" {
		fmt.Fprintf(out, "\n  ! %s\n", res.SigningKeyWarning)
	}
	line := strings.Repeat("─", 72)
	fmt.Fprintf(out, "\n%s\n", line)
	fmt.Fprintf(out, "Shown ONCE. Nothing below is stored in clear: copy it now.\n%s\n\n", line)
	fmt.Fprintf(out, "1. Administrator %q: choose the password with this link\n", res.AdminUsername)
	fmt.Fprintf(out, "   (single use, expires %s, i.e. in %s):\n\n   %s\n\n",
		res.ActivationExpires.Local().Format("15:04 MST"), time.Until(res.ActivationExpires).Round(time.Minute), res.ActivationURL)
	fmt.Fprintf(out, "   At the first sign-in, a second factor must be set up (MFA is required).\n\n")
	if res.ClientSecret != "" {
		fmt.Fprintf(out, "2. Admin console (admin/.env.local):\n\n")
		fmt.Fprintf(out, "   OIDC_ISSUER=%s/r/master\n", app.DevPublicURL())
		fmt.Fprintf(out, "   OIDC_CLIENT_ID=%s\n", res.ClientID)
		fmt.Fprintf(out, "   OIDC_CLIENT_SECRET=%s\n", res.ClientSecret)
		fmt.Fprintf(out, "   ADMIN_URL=%s\n\n", strings.TrimRight(adminURL, "/"))
	} else {
		fmt.Fprintf(out, "2. The admin console client already existed: its secret was not changed.\n")
		fmt.Fprintf(out, "   Lost it? `idp-admin recover client-secret` (all admins get an e-mail).\n\n")
	}
	fmt.Fprintf(out, "%s\n", line)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}


const recoverUsage = `usage:
  idp-admin recover admin --email <address>     create a NEW administrator account
  idp-admin recover client-secret               new secret for the admin console client
  idp-admin recover timeouts                    lift every timeout of the master realm

Break-glass only: every administrator receives an e-mail, the audit log
records who ran it (OS user and host). It needs an interactive terminal.
`

func runRecover(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, recoverUsage)
		return 2
	}
	return recoverCmd(args, os.Stdin, os.Stdout, isTerminal(os.Stdin) && isTerminal(os.Stdout))
}

// recoverCmd is runRecover with its input, output and terminal check
// injected (tests).
func recoverCmd(args []string, in io.Reader, out io.Writer, interactive bool) int {
	what := args[0]
	fs := flag.NewFlagSet("recover "+what, flag.ContinueOnError)
	fs.SetOutput(out)
	email := fs.String("email", "", "e-mail of the new administrator account")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch what {
	case "admin":
		if *email == "" {
			fmt.Fprintf(out, "error: --email is required\n\n%s", recoverUsage)
			return 2
		}
	case "client-secret", "timeouts":
	default:
		fmt.Fprintf(out, "unknown recover command %q\n\n%s", what, recoverUsage)
		return 2
	}

	// Guardrail: a person at a keyboard, typing a code read on the screen.
	// Not scriptable, not runnable by mistake from a pipeline.
	if !interactive {
		fmt.Fprintln(out, "refused: `idp-admin recover` needs an interactive terminal (stdin and stdout), it cannot run in a script")
		return 4
	}
	if !confirm(in, out, what) {
		fmt.Fprintln(out, "aborted: the code did not match, nothing was changed")
		return 5
	}
	if os.Getenv("DATABASE_URL") == "" {
		fmt.Fprintln(out, "error: DATABASE_URL is not set")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	notifierClient := app.EntClient()
	defer notifierClient.Close()
	admin, client := cliAdmin(app.CLINotifier(notifierClient))
	defer client.Close()

	switch what {
	case "admin":
		res, err := admin.RecoverAdmin(ctx, service.RecoverAdminInput{Email: *email, Actor: cliActor()})
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "\nNew administrator account %q (%d administrator(s) alerted by e-mail).\n", res.Username, res.AlertedAdmins)
		fmt.Fprintf(out, "Choose its password with this link (single use, expires in %s):\n\n  %s\n\n",
			time.Until(res.ActivationExpires).Round(time.Minute), res.ActivationURL)
		fmt.Fprintln(out, "Then remove or disable this account once regular access is back.")
	case "client-secret":
		secret, alerted, err := admin.RecoverClientSecret(ctx, cliActor())
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "\nNew secret of the admin console client (%d administrator(s) alerted by e-mail).\n", alerted)
		fmt.Fprintf(out, "The old one stopped working. Put this in admin/.env.local and restart the console:\n\n  OIDC_CLIENT_SECRET=%s\n\n", secret)
	case "timeouts":
		lifted, alerted, err := admin.RecoverTimeouts(ctx, cliActor())
		for _, v := range lifted {
			fmt.Fprintf(out, "  lifted: %s %s (%s)\n", v.TargetType, v.Target.Name, v.Reason)
		}
		if err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			return 1
		}
		if len(lifted) == 0 {
			fmt.Fprintln(out, "\nNo timeout in force or scheduled in the master realm: nothing to lift.")
			return 0
		}
		fmt.Fprintf(out, "\n%d timeout(s) of the master realm lifted (%d administrator(s) alerted by e-mail).\n", len(lifted), alerted)
		fmt.Fprintln(out, "Sessions revoked when they started stay revoked: sign in again.")
	}
	return 0
}

// confirm shows a random code and asks the operator to type it back.
func confirm(in io.Reader, out io.Writer, what string) bool {
	code := strings.ToUpper(rand.Text()[:6])
	fmt.Fprintf(out, "\n  ⚠  BREAK-GLASS PROCEDURE (%s)\n", what)
	fmt.Fprintln(out, "  Every administrator of the master realm will receive an e-mail,")
	fmt.Fprintln(out, "  and the audit log will record this OS user and host.")
	fmt.Fprintf(out, "\n  Type %s to continue: ", code)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return strings.TrimSpace(line) == code
}

// isTerminal: a character device (a terminal), not a pipe or a file.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
