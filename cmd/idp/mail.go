package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/app"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
)

// E-mail (Step 12). Configuration, all optional in development:
//
//	SMTP_HOST=mail.example.com        no SMTP_HOST: development prints e-mails in the
//	                                  log; production sends none (and turns off
//	                                  "forgot password", which needs e-mail)
//	SMTP_PORT=587                     default 587 (465 with SMTP_SECURITY=tls)
//	SMTP_SECURITY=starttls            starttls | tls | none (none: localhost only in production)
//	SMTP_USERNAME= / SMTP_PASSWORD=   empty: no authentication
//	SMTP_FROM=Oh-My-SSO <no-reply@example.com>     required in production
//	SMTP_HELO_NAME=                   name announced in EHLO (default "localhost")
//
//	idp mail test --to you@example.com   sends a test e-mail with these settings

const mailUsage = `usage:
  idp mail test --to <address>
`

// The e-mail builders moved to internal/app (Step 14), shared with
// cmd/idp-admin. These short names keep the CLI files unchanged.

func buildEmailSender(templates *notify.Templates) notify.EmailSender {
	return app.EmailSender(templates)
}

func loadTemplates() *notify.Templates { return app.Templates() }

// cliNotifier is the notifier of the CLI commands (`idp mfa reset`...): it
// sends right away, since the process ends with the command.
func cliNotifier(client *ent.Client) service.Notifier { return app.CLINotifier(client) }

func runMailCommand(args []string) int {
	if len(args) == 0 || args[0] != "test" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			fmt.Fprint(os.Stdout, mailUsage)
			return 0
		}
		fmt.Fprint(os.Stderr, mailUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	err := mailTest(ctx, args[1:], os.Stdout)
	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, mailUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

func mailTest(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mail test", flag.ContinueOnError)
	to := fs.String("to", "", "recipient (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return usageError{"--to is required"}
	}
	sender := buildEmailSender(loadTemplates())
	if sender == nil {
		return errors.New("SMTP_HOST is not set")
	}
	err := sender.Send(ctx, *to, notify.TemplateTest, notify.Data{
		Product: "Oh-My-SSO",
		When:    time.Now().UTC().Format("Mon 2 Jan 2006, 15:04 UTC"),
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "test e-mail sent to %s\n", *to)
	return nil
}
