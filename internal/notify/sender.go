package notify

import (
	"context"
	"errors"
	"log/slog"
)

// Template names an e-mail. The notification kinds of the core
// (domain.NotificationKind) use the same strings.
type Template string

const (
	TemplatePasswordReset          Template = "password_reset"
	TemplatePasswordChanged        Template = "password_changed"
	TemplateNewDeviceLogin         Template = "new_device_login"
	TemplateSuspiciousLogin        Template = "suspicious_login"
	TemplateMfaMethodAdded         Template = "mfa_method_added"
	TemplateMfaMethodRemoved       Template = "mfa_method_removed"
	TemplateMfaReset               Template = "mfa_reset"
	TemplateBackupCodesRegenerated Template = "backup_codes_regenerated"
	TemplateAccountLocked          Template = "account_locked"
	TemplateAppConnected Template = "app_connected"
	// TemplateTest is sent by `idp mail test` to check the SMTP settings.
	TemplateTest Template = "test"
	TemplateAccountInvite Template = "account_invite"
	TemplateAdminRecovery Template = "admin_recovery"
)

// AllTemplates lists every template: LoadTemplates parses each one at
// start-up.
var AllTemplates = []Template{
	TemplatePasswordReset, TemplatePasswordChanged, TemplateNewDeviceLogin,
	TemplateSuspiciousLogin, TemplateMfaMethodAdded, TemplateMfaMethodRemoved,
	TemplateMfaReset, TemplateBackupCodesRegenerated, TemplateAccountLocked,
	TemplateAppConnected, TemplateTest, TemplateAccountInvite, TemplateAdminRecovery,
}

// EmailSender sends one e-mail made from a template and its data.
type EmailSender interface {
	Send(ctx context.Context, to string, tmpl Template, data Data) error
}

// ErrPermanent marks a failure that retrying will not fix (bad address,
// template error, rejected credentials...). The dispatcher does not retry it.
var ErrPermanent = errors.New("notify: permanent failure")

// Message is a rendered e-mail, before MIME encoding.
type Message struct {
	Subject string
	Text    string // text/plain part
	HTML    string // text/html part
}

// LogEmailSender writes e-mails to the log instead of sending them. It is
// what the server uses in development when SMTP_HOST is not set, so the
// reset links can still be followed (never in production: the log would
// then hold valid reset links).
type LogEmailSender struct {
	Templates *Templates
	Logger    *slog.Logger
}

func (s *LogEmailSender) Send(ctx context.Context, to string, tmpl Template, data Data) error {
	msg, err := s.Templates.Render(tmpl, data)
	if err != nil {
		return errors.Join(ErrPermanent, err)
	}
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "e-mail (not sent: SMTP_HOST is not set)",
		"to", to, "template", string(tmpl), "subject", msg.Subject, "body", msg.Text)
	return nil
}
