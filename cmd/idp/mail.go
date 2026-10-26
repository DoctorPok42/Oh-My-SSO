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


const mailUsage = `usage:
  idp mail test --to <address>
`


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
