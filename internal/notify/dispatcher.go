package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Dispatcher turns the core's notification events into e-mails. It
// implements service.Notifier.
//
// Notify only puts the event in a queue (a buffered Go channel) and returns:
// the SMTP conversation happens in background workers. This matters for
// security, not only speed: if "forgot password" waited for the mail server
// when the account exists, its response time would reveal which accounts
// exist.
//
// The queue lives in memory. If the server stops while e-mails wait, they
// are lost (Close waits a little for them): acceptable for this content,
// the user can ask for another reset link, and alerts are best effort.
//
// Each e-mail actually attempted writes one AuditLog entry,
// action="notification_sent", with the recipient, the template and the
// outcome in details (status "sent" or "failed").
type Dispatcher struct {
	cfg      DispatcherConfig
	sender   EmailSender
	users    repository.UserRepository
	realms   repository.RealmRepository
	settings repository.InstanceSettingsRepository
	audit    repository.AuditLogRepository
	logger   *slog.Logger

	mu     sync.RWMutex // guards closed and sends on queue
	closed bool
	queue  chan domain.NotificationEvent
	wg     sync.WaitGroup
	ctx    context.Context // workers' context, cancelled by Close on timeout
	cancel context.CancelFunc
}

// DispatcherConfig tunes the dispatcher. Zero values get defaults.
type DispatcherConfig struct {
	PublicURL   string        // e.g. https://sso.example.com: base of the links in e-mails
	Product     string        // name shown in e-mails, default "Oh-My-SSO"
	QueueSize   int           // default 256
	Workers     int           // default 2
	MaxAttempts int           // per e-mail, default 3
	RetryDelay  time.Duration // attempt n waits n×RetryDelay first, default 5 s
}

// DispatcherDeps groups what the dispatcher reads and writes.
type DispatcherDeps struct {
	Sender   EmailSender
	Users    repository.UserRepository
	Realms   repository.RealmRepository
	Settings repository.InstanceSettingsRepository
	Audit    repository.AuditLogRepository
	Logger   *slog.Logger
}

// NewDispatcher builds a dispatcher; call Start to run its workers.
func NewDispatcher(cfg DispatcherConfig, d DispatcherDeps) *Dispatcher {
	if cfg.Product == "" {
		cfg.Product = "Oh-My-SSO"
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 5 * time.Second
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		cfg: cfg, sender: d.Sender, users: d.Users, realms: d.Realms,
		settings: d.Settings, audit: d.Audit, logger: d.Logger,
		queue: make(chan domain.NotificationEvent, cfg.QueueSize),
		ctx:   ctx, cancel: cancel,
	}
}

// Start runs the workers.
func (d *Dispatcher) Start() {
	for i := 0; i < d.cfg.Workers; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for e := range d.queue {
				if err := d.Process(d.ctx, e); err != nil {
					d.logger.Warn("notification not sent", "kind", e.Kind, "user_id", e.UserID, "error", err)
				}
			}
		}()
	}
}

// Notify queues an event (service.Notifier). It never blocks: when the
// queue is full the event is dropped, logged and audited.
func (d *Dispatcher) Notify(ctx context.Context, e domain.NotificationEvent) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	select {
	case d.queue <- e:
	default:
		d.logger.ErrorContext(ctx, "notification queue full, e-mail dropped", "kind", e.Kind, "user_id", e.UserID)
		d.writeAudit(context.WithoutCancel(ctx), e, "", "", 0, errors.New("queue full"))
	}
}

// Close stops accepting events, lets the workers send what is queued, and
// gives up when ctx ends.
func (d *Dispatcher) Close(ctx context.Context) {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		d.cancel() // stop retries in progress
		<-done
	}
	d.cancel()
}

// Process handles one event now, in the caller's goroutine (workers, tests).
// It returns nil when the e-mail is not wanted (switch off, unknown user).
func (d *Dispatcher) Process(ctx context.Context, e domain.NotificationEvent) error {
	tmpl, ok, err := d.template(ctx, e)
	if err != nil || !ok {
		return err
	}
	user, err := d.users.GetByID(ctx, e.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("notify: load user: %w", err)
	}
	if user.Email == "" {
		return nil
	}
	realm, err := d.realms.GetByID(ctx, e.RealmID)
	if err != nil {
		return fmt.Errorf("notify: load realm: %w", err)
	}

	data := d.data(e, user, realm)
	attempts, sendErr := d.send(ctx, user.Email, tmpl, data)
	d.writeAudit(ctx, e, user.Email, tmpl, attempts, sendErr)
	return sendErr
}

// template picks the e-mail for an event, or ok=false when the realm does
// not want it.
//
//	password_reset, password_changed  always (part of the reset flow)
//	every other kind                  only if notification_email_enabled
//	suspicious_login                  also needs suspicious_login_email_enabled;
//	                                  without it, a sign-in that was ALSO from a
//	                                  new device gets the "new device" e-mail
func (d *Dispatcher) template(ctx context.Context, e domain.NotificationEvent) (Template, bool, error) {
	if !e.Kind.IsSecurityAlert() {
		return Template(e.Kind), true, nil
	}
	st, err := d.settings.GetByRealmID(ctx, e.RealmID)
	if errors.Is(err, repository.ErrNotFound) {
		return "", false, nil // defaults: alerts off
	}
	if err != nil {
		return "", false, fmt.Errorf("notify: realm settings: %w", err)
	}
	if !st.NotificationEmailEnabled {
		return "", false, nil
	}
	if e.Kind == domain.NotificationSuspiciousLogin && !st.SuspiciousLoginEmailEnabled {
		if e.NewDevice {
			return TemplateNewDeviceLogin, true, nil
		}
		return "", false, nil
	}
	return Template(e.Kind), true, nil
}

func (d *Dispatcher) send(ctx context.Context, to string, tmpl Template, data Data) (int, error) {
	for attempt := 1; ; attempt++ {
		err := d.sender.Send(ctx, to, tmpl, data)
		if err == nil || errors.Is(err, ErrPermanent) || attempt >= d.cfg.MaxAttempts {
			return attempt, err
		}
		select {
		case <-time.After(time.Duration(attempt) * d.cfg.RetryDelay):
		case <-ctx.Done():
			return attempt, err
		}
	}
}

func (d *Dispatcher) writeAudit(ctx context.Context, e domain.NotificationEvent, to string, tmpl Template, attempts int, sendErr error) {
	if d.audit == nil {
		return
	}
	details := map[string]interface{}{
		"kind":     string(e.Kind),
		"template": string(tmpl),
		"to":       to,
		"attempts": attempts,
		"status":   "sent",
	}
	level, status := domain.AuditLogInfo, domain.AuditLogSuccess
	if sendErr != nil {
		details["status"] = "failed"
		details["error"] = sendErr.Error()
		level, status = domain.AuditLogWarning, domain.AuditLogFailure
	}
	if _, err := d.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      e.RealmID,
		UserID:       e.UserID,
		Action:       "notification_sent",
		ResourceType: "User",
		ResourceID:   e.UserID,
		Level:        level,
		Status:       status,
		Details:      details,
	}); err != nil {
		d.logger.WarnContext(ctx, "notification audit failed", "user_id", e.UserID, "error", err)
	}
}

// --- template data --------------------------------------------------------------

func (d *Dispatcher) data(e domain.NotificationEvent, user *domain.User, realm *domain.Realm) Data {
	out := Data{
		Product:           d.cfg.Product,
		Realm:             realm.DisplayName,
		Username:          user.Username,
		When:              formatTime(e.OccurredAt),
		IPAddress:         e.IPAddress,
		Device:            describeUserAgent(e.UserAgent),
		Location:          e.CountryName,
		ForgotPasswordURL: d.link(realm, "/auth/forgot-password"),
	}
	if out.Realm == "" {
		out.Realm = realm.Name
	}
	if out.Location == "" {
		out.Location = e.CountryCode
	}
	switch e.Kind {
	case domain.NotificationPasswordReset:
		// The token goes after "#": browsers never send that part to the
		// server, so it cannot end up in access logs. The page reads it
		// with JavaScript.
		out.ResetURL = d.link(realm, "/auth/reset-password") + "#token=" + url.QueryEscape(e.ResetToken)
		out.ExpiresIn = humanDuration(e.ExpiresAt.Sub(e.OccurredAt))
	case domain.NotificationMfaMethodAdded, domain.NotificationMfaMethodRemoved:
		out.MethodLabel = methodLabel(e.MfaMethodType)
		out.MethodName = e.MfaMethodName
	case domain.NotificationAccountLocked:
		out.LockedUntil = formatTime(e.ExpiresAt)
		out.LockDuration = humanDuration(e.ExpiresAt.Sub(e.OccurredAt))
		out.FailedAttempts = e.FailedAttempts
	case domain.NotificationSuspiciousLogin:
		for _, r := range e.SuspiciousReasons {
			out.Reasons = append(out.Reasons, reasonText(r, out.Location))
		}
	case domain.NotificationAppConnected:
		out.AppName = e.ClientName
		out.AppAccess = e.Access
		out.AppAccessAdded = e.AccessAdded
	case domain.NotificationAccountInvite:
		// Same page and same one-time tokens as a password reset (Step 14).
		out.ResetURL = d.link(realm, "/auth/reset-password") + "#token=" + url.QueryEscape(e.ResetToken)
		out.ExpiresIn = humanDuration(e.ExpiresAt.Sub(e.OccurredAt))
	case domain.NotificationAdminRecovery:
		out.RecoveryKind = e.RecoveryKind
		out.RecoveryActor = e.RecoveryActor
		out.RecoveryAccount = e.RecoveryAccount
	}
	return out
}

func (d *Dispatcher) link(realm *domain.Realm, path string) string {
	return d.cfg.PublicURL + "/r/" + url.PathEscape(realm.Name) + path
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("Mon 2 Jan 2006, 15:04 UTC")
}

// humanDuration: "30 minutes", "1 hour", "2 hours 30 minutes".
func humanDuration(d time.Duration) string {
	m := int((d + 30*time.Second) / time.Minute) // rounded to the minute
	if m < 1 {
		m = 1
	}
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	h, m := m/60, m%60
	switch {
	case h == 0:
		return plural(m, "minute")
	case m == 0:
		return plural(h, "hour")
	default:
		return plural(h, "hour") + " " + plural(m, "minute")
	}
}

func methodLabel(t domain.MfaMethodType) string {
	switch t {
	case domain.MfaMethodTOTP:
		return "authenticator app"
	case domain.MfaMethodPasskey:
		return "passkey"
	case domain.MfaMethodWebAuthn:
		return "security key"
	case domain.MfaMethodBackupCodes:
		return "backup codes"
	default:
		return string(t)
	}
}

func reasonText(reason, location string) string {
	switch reason {
	case domain.SuspiciousNewCountry:
		if location != "" {
			return "it came from a country you have not signed in from before (" + location + ")"
		}
		return "it came from a country you have not signed in from before"
	case domain.SuspiciousUnusualHour:
		return "it happened at an unusual time of day for you"
	case domain.SuspiciousNewNetworkAndDevice:
		return "it came from a new device on a network you have not used before"
	default:
		return reason
	}
}
