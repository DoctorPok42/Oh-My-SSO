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

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
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
// action="notification.sent" (actor: system, target: the recipient), with the recipient, the template and the
// outcome in details (status "sent" or "failed").
type Dispatcher struct {
	cfg      DispatcherConfig
	sender   EmailSender
	users    repository.UserRepository
	realms   repository.RealmRepository
	settings repository.InstanceSettingsRepository
	audit    repository.AuditLogRepository
	logger   *slog.Logger
	i18n     *i18n.Bundle

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
	// I18n: the languages of the e-mails (nil: the embedded ones).
	I18n *i18n.Bundle
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
	if d.I18n == nil {
		d.I18n = i18n.MustDefault()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		cfg: cfg, sender: d.Sender, users: d.Users, realms: d.Realms,
		settings: d.Settings, audit: d.Audit, logger: d.Logger, i18n: d.I18n,
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

	data := d.data(d.localizer(ctx, user, realm.ID), e, user, realm)
	if d.settings != nil {
		// The realm's sender (name, address, reply-to) and image. Without
		// a row, or when it cannot be read, the server default applies:
		// a settings failure must not stop a password reset.
		if st, err := d.settings.GetByRealmID(ctx, realm.ID); err == nil {
			data.ApplyRealmSettings(st)
		}
	}
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
		ActorType:    domain.AuditActorSystem, // the server sends; the user receives
		TargetUserID: e.UserID,
		Action:       audit.NotificationSent,
		ResourceType: "User",
		ResourceID:   e.UserID,
		Level:        level,
		Status:       status,
		Details:      details,
	}); err != nil {
		d.logger.WarnContext(ctx, "notification audit failed", "user_id", e.UserID, "error", err)
	}
}


// localizer: the language of an e-mail to user. The one they chose in the
// account console (profile "locale"), else the realm's default language
// (Settings), else English (package i18n). Unlike a page, an e-mail has no
// browser to ask.
func (d *Dispatcher) localizer(ctx context.Context, user *domain.User, realmID string) *i18n.Localizer {
	if l, _ := user.Profile["locale"].(string); d.i18n.Supported(l) {
		return d.i18n.Get(l)
	}
	if d.settings == nil {
		return d.i18n.Get(i18n.English)
	}
	if st, err := d.settings.GetByRealmID(ctx, realmID); err == nil && d.i18n.Supported(st.DefaultLocale) {
		return d.i18n.Get(st.DefaultLocale)
	}
	return d.i18n.Get(i18n.English)
}

func (d *Dispatcher) data(loc *i18n.Localizer, e domain.NotificationEvent, user *domain.User, realm *domain.Realm) Data {
	out := Data{
		Lang:              loc.Lang(),
		Product:           d.cfg.Product,
		Realm:             realm.DisplayName,
		Username:          user.Username,
		When:              formatTime(loc, e.OccurredAt),
		IPAddress:         e.IPAddress,
		Device:            describeUserAgent(loc, e.UserAgent),
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
		out.ExpiresIn = humanDuration(loc, e.ExpiresAt.Sub(e.OccurredAt))
	case domain.NotificationMfaMethodAdded, domain.NotificationMfaMethodRemoved:
		out.MethodLabel = methodLabel(loc, e.MfaMethodType)
		out.MethodName = e.MfaMethodName
	case domain.NotificationAccountLocked:
		out.LockedUntil = formatTime(loc, e.ExpiresAt)
		out.LockDuration = humanDuration(loc, e.ExpiresAt.Sub(e.OccurredAt))
		out.FailedAttempts = e.FailedAttempts
	case domain.NotificationSuspiciousLogin:
		for _, r := range e.SuspiciousReasons {
			out.Reasons = append(out.Reasons, reasonText(loc, r, out.Location, e.MfaMethodType))
		}
	case domain.NotificationAppConnected:
		out.AppName = e.ClientName
		for _, a := range e.Access {
			out.AppAccess = append(out.AppAccess, knownText(loc, accessTexts, a))
		}
		out.AppAccessAdded = e.AccessAdded
	case domain.NotificationAccountInvite:
		out.ResetURL = d.link(realm, "/auth/reset-password") + "#token=" + url.QueryEscape(e.ResetToken)
		out.ExpiresIn = humanDuration(loc, e.ExpiresAt.Sub(e.OccurredAt))
	case domain.NotificationAdminRecovery:
		out.RecoveryKind = knownText(loc, recoveryKinds, e.RecoveryKind)
		out.RecoveryActor = e.RecoveryActor
		out.RecoveryAccount = e.RecoveryAccount
	}
	return out
}

func (d *Dispatcher) link(realm *domain.Realm, path string) string {
	return d.cfg.PublicURL + "/r/" + url.PathEscape(realm.Name) + path
}

// formatTime: "Mon 2 Jan 2006, 15:04 UTC", in the e-mail's language.
func formatTime(loc *i18n.Localizer, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return loc.LongDateTime(t)
}

// humanDuration: "30 minutes", "1 hour", "2 hours 30 minutes".
func humanDuration(loc *i18n.Localizer, d time.Duration) string { return loc.Duration(d) }

func methodLabel(loc *i18n.Localizer, t domain.MfaMethodType) string {
	switch t {
	case domain.MfaMethodTOTP:
		return loc.T("email.method.totp", "authenticator app")
	case domain.MfaMethodPasskey:
		return loc.T("email.method.passkey", "passkey")
	case domain.MfaMethodWebAuthn:
		return loc.T("email.method.security_key", "security key")
	case domain.MfaMethodBackupCodes:
		return loc.T("email.method.backup_codes", "backup codes")
	default:
		return string(t)
	}
}

func reasonText(loc *i18n.Localizer, reason, location string, method domain.MfaMethodType) string {
	switch reason {
	case domain.SuspiciousNewSignInMethod:
		if method != "" {
			return loc.T("email.reason.new_method_named", "it used a sign-in method you have not used recently ({method})", "method", methodLabel(loc, method))
		}
		return loc.T("email.reason.new_method", "it used a sign-in method you have not used recently")
	case domain.SuspiciousNewCountry:
		if location != "" {
			return loc.T("email.reason.new_country_named", "it came from a country you have not signed in from before ({country})", "country", location)
		}
		return loc.T("email.reason.new_country", "it came from a country you have not signed in from before")
	case domain.SuspiciousUnusualHour:
		return loc.T("email.reason.unusual_hour", "it happened at an unusual time of day for you")
	case domain.SuspiciousNewNetworkAndDevice:
		return loc.T("email.reason.new_network_device", "it came from a new device on a network you have not used before")
	default:
		return reason
	}
}

// Texts that reach the dispatcher already written, in English, by the
// core: translated when they are one of these, kept as they are otherwise
// (a scope description written by an administrator).
var (
	// accessTexts: the standard lines of the consent page (adapters oidc
	// and saml).
	accessTexts = []i18n.Text{
		i18n.M("consent.scope.profile.title", "Your profile"),
		i18n.M("consent.scope.email.title", "Your e-mail address"),
		i18n.M("consent.scope.offline_access.title", "Stay signed in"),
	}
	// recoveryKinds: what `idp-admin recover` did (service.alertAdmins).
	recoveryKinds = []i18n.Text{
		i18n.M("email.recovery.kind.new_admin", "a new administrator account"),
		i18n.M("email.recovery.kind.new_secret", "a new secret for the admin console"),
		i18n.M("email.recovery.kind.timeouts_lifted", "every timeout of the master realm lifted"),
	}
)

func knownText(loc *i18n.Localizer, known []i18n.Text, english string) string {
	for _, t := range known {
		if t.Default == english {
			return loc.Text(t)
		}
	}
	return english
}
