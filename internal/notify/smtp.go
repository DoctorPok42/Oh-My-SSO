package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"time"
)

// SMTP sending with the standard library (net/smtp): no dependency.
//
// How an e-mail leaves the server (RFC 5321):
//
//	connect host:port ──► EHLO ──► STARTTLS (587) ──► AUTH PLAIN user/pass
//	  ──► MAIL FROM:<from> ──► RCPT TO:<to> ──► DATA <message> . ──► QUIT
//
// Two ways to encrypt (RFC 8314):
//   - "starttls" (port 587, "submission"): the connection starts in clear
//     and switches to TLS before anything secret is sent. We REFUSE to
//     continue if the server does not offer STARTTLS.
//   - "tls" (port 465, "submissions"): TLS from the first byte. Recommended
//     by RFC 8314 when the server supports it.
//   - "none": no encryption at all. Only for a mail catcher on your own
//     machine (Mailpit on localhost:1025); refused in production.
//
// https://pkg.go.dev/net/smtp
// https://datatracker.ietf.org/doc/html/rfc8314

// Security is how the SMTP connection is encrypted.
type Security string

const (
	SecuritySTARTTLS Security = "starttls"
	SecurityTLS      Security = "tls"
	SecurityNone     Security = "none"
)

// SMTPConfig is read from SMTP_* environment variables (cmd/idp).
type SMTPConfig struct {
	Host     string
	Port     int
	Username string // empty: no authentication
	Password string
	Security Security
	// From is the sender, "Name <address>" or just "address".
	From string
	// HeloName is the name we give in EHLO (default "localhost"). Some
	// servers want a real host name.
	HeloName string
	Timeout  time.Duration // whole conversation; default 30 s
}

// SMTPEmailSender implements EmailSender over SMTP.
type SMTPEmailSender struct {
	cfg       SMTPConfig
	from      *mail.Address
	templates *Templates
	now       func() time.Time
}

// NewSMTPEmailSender checks the configuration. It does not connect: use
// `idp mail test` to try the settings.
func NewSMTPEmailSender(cfg SMTPConfig, templates *Templates) (*SMTPEmailSender, error) {
	if cfg.Host == "" {
		return nil, errors.New("notify: SMTP host is required")
	}
	switch cfg.Security {
	case "":
		cfg.Security = SecuritySTARTTLS
		if cfg.Port == 465 {
			cfg.Security = SecurityTLS
		}
	case SecuritySTARTTLS, SecurityTLS, SecurityNone:
	default:
		return nil, fmt.Errorf("notify: SMTP security %q: use starttls, tls or none", cfg.Security)
	}
	if cfg.Port == 0 {
		cfg.Port = 587
		if cfg.Security == SecurityTLS {
			cfg.Port = 465
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("notify: SMTP port %d is invalid", cfg.Port)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.HeloName == "" {
		cfg.HeloName = "localhost"
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("notify: SMTP_FROM %q is not an e-mail address: %w", cfg.From, err)
	}
	if templates == nil {
		return nil, errors.New("notify: templates are required")
	}
	return &SMTPEmailSender{cfg: cfg, from: from, templates: templates, now: time.Now}, nil
}

// Config returns the effective configuration (defaults applied).
func (s *SMTPEmailSender) Config() SMTPConfig { return s.cfg }

// Send renders the template and delivers the e-mail.
func (s *SMTPEmailSender) Send(ctx context.Context, to string, tmpl Template, data Data) error {
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return errors.Join(ErrPermanent, fmt.Errorf("notify: recipient %q: %w", to, err))
	}
	msg, err := s.templates.Render(tmpl, data)
	if err != nil {
		return errors.Join(ErrPermanent, err)
	}
	raw, err := buildMIME(s.from, rcpt, msg, s.now())
	if err != nil {
		return errors.Join(ErrPermanent, err)
	}
	return s.deliver(ctx, rcpt.Address, raw)
}

func (s *SMTPEmailSender) deliver(ctx context.Context, rcpt string, raw []byte) error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	deadline := time.Now().Add(s.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	tlsConfig := &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}

	dialer := &net.Dialer{Deadline: deadline}
	var conn net.Conn
	var err error
	if s.cfg.Security == SecurityTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("notify: connect to %s: %w", addr, err)
	}
	// One deadline for the whole conversation: a server that stops
	// answering cannot block a worker forever.
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notify: smtp greeting: %w", err)
	}
	defer c.Close()

	if err := c.Hello(s.cfg.HeloName); err != nil {
		return fmt.Errorf("notify: EHLO: %w", err)
	}
	if s.cfg.Security == SecuritySTARTTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.Join(ErrPermanent, fmt.Errorf("notify: %s does not offer STARTTLS; refusing to send in clear (set SMTP_SECURITY=tls for port 465)", addr))
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("notify: STARTTLS: %w", err)
		}
	}
	if s.cfg.Username != "" {
		// PlainAuth refuses to send the password over a connection that
		// is not encrypted (except to localhost).
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return classify(fmt.Errorf("notify: AUTH: %w", err))
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return classify(fmt.Errorf("notify: MAIL FROM: %w", err))
	}
	if err := c.Rcpt(rcpt); err != nil {
		return classify(fmt.Errorf("notify: RCPT TO: %w", err))
	}
	w, err := c.Data()
	if err != nil {
		return classify(fmt.Errorf("notify: DATA: %w", err))
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("notify: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return classify(fmt.Errorf("notify: end of message: %w", err))
	}
	return c.Quit()
}

// classify marks 5xx SMTP replies as permanent (RFC 5321 §4.2.1: 4xx means
// "try again later", 5xx means "this will never work").
func classify(err error) error {
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) && tpErr.Code >= 500 && tpErr.Code < 600 {
		return errors.Join(ErrPermanent, err)
	}
	return err
}
