package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/storage/entstore"
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

// buildEmailSender returns the sender configured by SMTP_*, or nil when
// e-mail is off.
func buildEmailSender(templates *notify.Templates) notify.EmailSender {
	appEnv := os.Getenv("APP_ENV")
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		if appEnv == "development" {
			log.Printf("mail: SMTP_HOST is not set: e-mails are printed in this log instead (development only)")
			return &notify.LogEmailSender{Templates: templates, Logger: slog.Default()}
		}
		log.Printf("mail: SMTP_HOST is not set: no e-mail is sent, \"forgot password\" is disabled")
		return nil
	}

	port := 0
	if p := os.Getenv("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			log.Fatalf("mail: SMTP_PORT %q is not a number", p)
		}
		port = n
	}
	from := unquote(os.Getenv("SMTP_FROM"))
	if from == "" {
		if appEnv == "production" {
			log.Fatalf("mail: SMTP_FROM is required when APP_ENV=production")
		}
		from = "Oh-My-SSO <no-reply@localhost>"
	}
	security := notify.Security(strings.ToLower(os.Getenv("SMTP_SECURITY")))
	if security == notify.SecurityNone && appEnv == "production" && !isLoopbackHost(host) {
		log.Fatalf("mail: SMTP_SECURITY=none sends passwords and reset links in clear: refused in production (except to localhost)")
	}

	sender, err := notify.NewSMTPEmailSender(notify.SMTPConfig{
		Host:     host,
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		Security: security,
		From:     from,
		HeloName: os.Getenv("SMTP_HELO_NAME"),
	}, templates)
	if err != nil {
		log.Fatalf("mail: %v", err)
	}
	cfg := sender.Config()
	log.Printf("mail: SMTP %s:%d (%s), from %s", cfg.Host, cfg.Port, cfg.Security, cfg.From)
	return sender
}

// unquote removes quotes around a whole value (SMTP_FROM="A <a@b>" read by
// a tool that keeps them, like make), but not quotes inside it.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadTemplates() *notify.Templates {
	t, err := notify.LoadTemplates()
	if err != nil {
		log.Fatalf("mail: %v", err) // embedded files: only a broken build gets here
	}
	return t
}

// newDispatcher wires the dispatcher on the database.
func newDispatcher(client *ent.Client, publicURL string, sender notify.EmailSender) *notify.Dispatcher {
	return notify.NewDispatcher(notify.DispatcherConfig{PublicURL: publicURL}, notify.DispatcherDeps{
		Sender:   sender,
		Users:    entstore.NewUserRepository(client),
		Realms:   entstore.NewRealmRepository(client),
		Settings: entstore.NewInstanceSettingsRepository(client),
		Audit:    entstore.NewAuditLogRepository(client),
	})
}

// cliNotifier is the notifier of the CLI commands (`idp mfa reset`...): it
// sends right away, since the process ends with the command.
func cliNotifier(client *ent.Client) service.Notifier {
	sender := buildEmailSender(loadTemplates())
	if sender == nil {
		return service.NopNotifier{}
	}
	return syncNotifier{d: newDispatcher(client, devPublicURL(), sender)}
}

type syncNotifier struct{ d *notify.Dispatcher }

func (n syncNotifier) Notify(ctx context.Context, e domain.NotificationEvent) {
	if err := n.d.Process(ctx, e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: e-mail not sent: %v\n", err)
	}
}

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
