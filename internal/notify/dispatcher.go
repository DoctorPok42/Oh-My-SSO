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

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// Dispatcher turns the core's notification events into e-mails. It
// implements service.Notifier.
//
// Notify writes the e-mail to the outbox, a table of the database
// (repository.EmailOutboxRepository), and returns: the SMTP conversation
// happens in background workers. This matters for security, not only speed:
// if "forgot password" waited for the mail server when the account exists,
// its response time would reveal which accounts exist.
//
// The outbox makes an e-mail outlive a mail server outage and a restart
// (audit B-12). The workers of every server take the due e-mails one at a
// time (Claim: never twice at once), send each once per attempt, and when
// the mail server fails, try again later: 30 s, 1 min, 2 min... doubling up
// to every 2 h, for 24 h, or until the link the e-mail carries expires,
// whichever comes first. An e-mail is "sent", "failed" (refused for good, or
// out of time) or "cancelled" (its link was used or replaced in between, the
// account is gone, the realm switched the alert off). Delivery is at least
// once: a server that dies between the mail server's answer and the update
// of the row sends that e-mail again.
//
// The link of a reset, activation or verification e-mail is the only secret:
// it is sealed (Sealer, envelope encryption) and bound to its row.
//
// Each e-mail writes one AuditLog entry when it ends, action
// "notification.sent" (actor: system, target: the recipient), with the
// recipient, the template, the attempts and the outcome in details (status
// "sent" or "failed"). The successes of a batch do not
// (NotificationEvent.QuietAudit). An attempt that will be retried is logged,
// not audited.
type Dispatcher struct {
	cfg      DispatcherConfig
	sender   EmailSender
	users    repository.UserRepository
	realms   repository.RealmRepository
	settings repository.InstanceSettingsRepository
	audit    repository.AuditLogRepository
	outbox   repository.EmailOutboxRepository
	sealer   Sealer
	links    LinkTracker
	logger   *slog.Logger
	i18n     *i18n.Bundle
	now      func() time.Time

	mu      sync.RWMutex // guards closed
	closed  bool
	started bool
	wake    chan struct{} // a new e-mail is in the outbox
	stop    chan struct{} // closed by Close: no new claims
	wg      sync.WaitGroup
	ctx     context.Context // workers' context, cancelled by Close on timeout
	cancel  context.CancelFunc
}

// DispatcherConfig tunes the dispatcher. Zero values get defaults.
type DispatcherConfig struct {
	PublicURL string // e.g. https://sso.example.com: base of the links in e-mails
	Product   string // name shown in e-mails, default "Oh-My-SSO"
	Workers   int    // default 2

	// The outbox. PollInterval: how often an idle worker looks for due
	// e-mails (retries, and e-mails another process wrote), default 10 s.
	// Lease: how long a worker holds an e-mail it is sending, default 2 min
	// (another one takes it over after: the first one died). GiveUpAfter:
	// default 24 h. FirstRetry, MaxRetry: the delay after the first failed
	// attempt (default 30 s), doubled at each attempt up to MaxRetry
	// (default 2 h).
	PollInterval time.Duration
	Lease        time.Duration
	GiveUpAfter  time.Duration
	FirstRetry   time.Duration
	MaxRetry     time.Duration

	// Process only (an e-mail sent at once, without the outbox).
	MaxAttempts int           // default 3
	RetryDelay  time.Duration // attempt n waits n×RetryDelay first, default 5 s
}

// Sealer keeps the link of an e-mail encrypted in the outbox
// (service.EnvelopeService).
type Sealer interface {
	Seal(ctx context.Context, realmID string, plaintext, aad []byte) (string, error)
	Open(ctx context.Context, sealed string, aad []byte) ([]byte, error)
}

// LinkTracker knows the links the e-mails carry (domain.NotificationKind.
// CarriesLink). token is the raw link token.
type LinkTracker interface {
	// Usable: the link still works (exists, not used, not expired). An
	// e-mail whose link no longer works is not sent.
	Usable(ctx context.Context, kind domain.NotificationKind, token string) (bool, error)
	// Emailed: the e-mail carrying the link left, to address (a reset or
	// activation link used afterwards proves the user reads that address).
	Emailed(ctx context.Context, kind domain.NotificationKind, token, address string) error
}

// DispatcherDeps groups what the dispatcher reads and writes.
type DispatcherDeps struct {
	Sender   EmailSender
	Users    repository.UserRepository
	Realms   repository.RealmRepository
	Settings repository.InstanceSettingsRepository
	Audit    repository.AuditLogRepository
	// Outbox: required for Notify, NotifyWait, Start (not for Process).
	Outbox repository.EmailOutboxRepository
	// Sealer: required to queue an e-mail with a link.
	Sealer Sealer
	// Links: optional; without it a link is sent whatever became of it.
	Links  LinkTracker
	Logger *slog.Logger
	// I18n: the languages of the e-mails (nil: the embedded ones).
	I18n *i18n.Bundle
	Now  func() time.Time // optional (tests)
}

// ErrDispatcherClosed: Close was called.
var ErrDispatcherClosed = errors.New("notify: dispatcher closed")

// NewDispatcher builds a dispatcher; call Start to run its workers.
func NewDispatcher(cfg DispatcherConfig, d DispatcherDeps) *Dispatcher {
	if cfg.Product == "" {
		cfg.Product = "Oh-My-SSO"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 2 * time.Minute
	}
	if cfg.GiveUpAfter <= 0 {
		cfg.GiveUpAfter = domain.OutboxGiveUpAfter
	}
	if cfg.FirstRetry <= 0 {
		cfg.FirstRetry = 30 * time.Second
	}
	if cfg.MaxRetry <= 0 {
		cfg.MaxRetry = 2 * time.Hour
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
	if d.Now == nil {
		d.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		cfg: cfg, sender: d.Sender, users: d.Users, realms: d.Realms,
		settings: d.Settings, audit: d.Audit, outbox: d.Outbox, sealer: d.Sealer, links: d.Links,
		logger: d.Logger, i18n: d.I18n, now: d.Now,
		wake: make(chan struct{}, 1), stop: make(chan struct{}),
		ctx: ctx, cancel: cancel,
	}
}

// Start runs the workers. They send what the outbox holds, the e-mails left
// by a previous run included.
func (d *Dispatcher) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started || d.closed || d.outbox == nil {
		return
	}
	d.started = true
	for i := 0; i < d.cfg.Workers; i++ {
		d.wg.Add(1)
		go d.work()
	}
}

func (d *Dispatcher) work() {
	defer d.wg.Done()
	for {
		select {
		case <-d.stop:
			return
		default:
		}
		if d.deliverNext() {
			continue
		}
		select {
		case <-d.stop:
			return
		case <-d.wake:
		case <-time.After(d.cfg.PollInterval):
		}
	}
}

// Notify queues an event (service.Notifier). It does not wait for the mail
// server. When the e-mail cannot be written to the outbox (database down),
// it is lost: logged and audited.
func (d *Dispatcher) Notify(ctx context.Context, e domain.NotificationEvent) {
	ctx = context.WithoutCancel(ctx) // the request may end before the row is written
	if _, err := d.Enqueue(ctx, e); err != nil {
		d.logger.ErrorContext(ctx, "e-mail not queued", "kind", e.Kind, "user_id", e.UserID, "error", err)
		d.writeAudit(ctx, inBatch(ctx, e), "", "", 0, fmt.Errorf("not queued: %w", err))
	}
}

// NotifyWait is Notify that tells whether the e-mail was queued
// (service.QueueNotifier): an invitation that was not shows its link
// instead.
func (d *Dispatcher) NotifyWait(ctx context.Context, e domain.NotificationEvent) error {
	_, err := d.Enqueue(ctx, e)
	return err
}

// Enqueue writes the e-mail of an event to the outbox and returns its id;
// "" with no error when the realm does not want this e-mail. The workers
// send it.
func (d *Dispatcher) Enqueue(ctx context.Context, e domain.NotificationEvent) (string, error) {
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()
	if closed {
		return "", ErrDispatcherClosed
	}
	if d.outbox == nil {
		return "", errors.New("notify: no outbox")
	}
	e = inBatch(ctx, e)
	// Not wanted (alerts off): nothing to keep. Checked again when it leaves.
	if _, ok, err := d.template(ctx, e); err != nil {
		return "", err
	} else if !ok {
		return "", nil
	}
	now := d.now()
	row := &domain.OutboxEmail{
		ID: uuid.NewString(), RealmID: e.RealmID, UserID: e.UserID, Kind: e.Kind, Event: e,
		Status: domain.OutboxPending, NextAttemptAt: now, Deadline: d.deadline(e, now), CreatedAt: now,
	}
	if e.ResetToken != "" {
		if d.sealer == nil {
			return "", errors.New("notify: cannot keep a link without encryption")
		}
		sealed, err := d.sealer.Seal(ctx, e.RealmID, []byte(e.ResetToken), outboxAAD(row.ID))
		if err != nil {
			return "", fmt.Errorf("notify: seal link: %w", err)
		}
		row.SealedToken = sealed
	}
	row.Event.ResetToken = ""
	if err := d.outbox.Create(ctx, row); err != nil {
		return "", fmt.Errorf("notify: outbox: %w", err)
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return row.ID, nil
}

// deadline: when to give up on an e-mail asked for at now. Its link (if
// any) is worth nothing once expired.
func (d *Dispatcher) deadline(e domain.NotificationEvent, now time.Time) time.Time {
	return domain.OutboxDeadline(e, now, d.cfg.GiveUpAfter)
}

// Wake makes an idle worker look at the outbox now (an e-mail put back in
// the queue).
func (d *Dispatcher) Wake() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// outboxAAD binds a sealed link to its row: copied onto another row, it
// does not open.
func outboxAAD(id string) []byte { return []byte("email_outbox:" + id) }

// retryDelay: the wait after the n-th failed attempt (n >= 1).
func (d *Dispatcher) retryDelay(n int) time.Duration {
	delay := d.cfg.FirstRetry
	for i := 1; i < n && delay < d.cfg.MaxRetry; i++ {
		delay *= 2
	}
	return min(delay, d.cfg.MaxRetry)
}

// inBatch: an e-mail queued by a bulk action is recorded in the one audit
// entry of the action, not in an entry of its own (unless it fails).
func inBatch(ctx context.Context, e domain.NotificationEvent) domain.NotificationEvent {
	b := audit.BatchOf(ctx)
	if b == nil || e.OperationID != "" {
		return e
	}
	if b.Add(audit.Entry{
		Action: audit.NotificationSent, ResourceType: "User", ResourceID: e.UserID, TargetUserID: e.UserID,
		Details: map[string]interface{}{"kind": string(e.Kind), "status": "queued"},
	}) {
		e.QuietAudit = true
	}
	e.OperationID = b.Operation()
	return e
}

// Close stops taking e-mails from the outbox, lets the workers finish the
// ones they are sending, and gives up on them when ctx ends. What is left
// stays in the outbox for the next start (or another server).
func (d *Dispatcher) Close(ctx context.Context) {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.stop)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		d.cancel() // abort the SMTP conversations in progress
		<-done
	}
	d.cancel()
}

// deliverNext sends the most overdue e-mail of the outbox, if any, and
// reports whether there was one.
func (d *Dispatcher) deliverNext() bool {
	row, err := d.outbox.Claim(d.ctx, "", d.now(), d.cfg.Lease)
	if errors.Is(err, repository.ErrNotFound) {
		return false
	}
	if err != nil {
		if d.ctx.Err() == nil {
			d.logger.Warn("e-mail outbox not readable", "error", err)
		}
		return false
	}
	_ = d.deliver(d.ctx, row)
	return true
}

// DeliverNow sends one e-mail of the outbox now, in the caller's goroutine
// (a command-line tool that ends right after). It returns why it did not
// leave; an e-mail that failed for a while stays in the outbox, and the
// servers try again. An e-mail another dispatcher holds is left to it.
func (d *Dispatcher) DeliverNow(ctx context.Context, id string) error {
	if d.outbox == nil {
		return errors.New("notify: no outbox")
	}
	row, err := d.outbox.Claim(ctx, id, d.now(), d.cfg.Lease)
	if errors.Is(err, repository.ErrNotFound) {
		return nil // taken by a server, or no longer due
	}
	if err != nil {
		return err
	}
	return d.deliver(ctx, row)
}

// errNotWanted, errGone...: why an e-mail is cancelled (outbox.last_error).
var (
	errNotWanted = errors.New("the realm no longer sends this e-mail")
	errNoAccount = errors.New("the account no longer exists")
	errNoAddress = errors.New("the account has no e-mail address")
	errLinkGone  = errors.New("its link was used, replaced or has expired")
)

// deliver makes one attempt at a claimed e-mail and records the outcome.
func (d *Dispatcher) deliver(ctx context.Context, row *domain.OutboxEmail) error {
	e := row.Event
	e.Kind, e.RealmID, e.UserID = row.Kind, row.RealmID, row.UserID
	// The row is updated even when ctx ends (the server stops): briefly.
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if row.SealedToken != "" {
		raw, err := d.openLink(ctx, row)
		if err != nil {
			return d.retryOrFail(save, ctx, row, e, "", "", err)
		}
		e.ResetToken = raw
	}
	if e.Kind.CarriesLink() && d.links != nil {
		ok, err := d.links.Usable(ctx, e.Kind, e.ResetToken)
		if err != nil {
			return d.retryOrFail(save, ctx, row, e, "", "", fmt.Errorf("check link: %w", err))
		}
		if !ok {
			return d.cancelled(save, row, errLinkGone)
		}
	}
	to, tmpl, data, err := d.compose(ctx, e)
	switch {
	case errors.Is(err, errNotWanted), errors.Is(err, errNoAccount), errors.Is(err, errNoAddress):
		return d.cancelled(save, row, err)
	case err != nil:
		return d.retryOrFail(save, ctx, row, e, "", "", err)
	}

	sendErr := d.sender.Send(ctx, to, tmpl, data)
	if sendErr != nil {
		return d.retryOrFail(save, ctx, row, e, to, tmpl, sendErr)
	}
	if err := d.outbox.Sent(save, row.ID, to, string(tmpl), d.now()); err != nil {
		d.logger.Error("e-mail sent but not marked sent: it may be sent again", "outbox_id", row.ID, "error", err)
	}
	if e.Kind.CarriesLink() && d.links != nil {
		if err := d.links.Emailed(save, e.Kind, e.ResetToken, to); err != nil {
			d.logger.Warn("link e-mailed but not recorded", "outbox_id", row.ID, "error", err)
		}
	}
	d.writeAudit(save, e, to, tmpl, row.Attempts, nil)
	return nil
}

// openLink decrypts the link of an e-mail. A link that cannot be decrypted
// will never be: a permanent failure.
func (d *Dispatcher) openLink(ctx context.Context, row *domain.OutboxEmail) (string, error) {
	if d.sealer == nil {
		return "", errors.Join(ErrPermanent, errors.New("cannot decrypt the link: no encryption"))
	}
	raw, err := d.sealer.Open(ctx, row.SealedToken, outboxAAD(row.ID))
	if err != nil {
		return "", errors.Join(ErrPermanent, fmt.Errorf("cannot decrypt the link: %w", err))
	}
	return string(raw), nil
}

// retryOrFail records a failed attempt: later when there is time left,
// failed otherwise (or when the failure is permanent).
func (d *Dispatcher) retryOrFail(save, ctx context.Context, row *domain.OutboxEmail, e domain.NotificationEvent, to string, tmpl Template, cause error) error {
	now := d.now()
	if ctx.Err() != nil && !errors.Is(cause, ErrPermanent) {
		// The server is stopping: not the mail server's fault. Due again at
		// once for the next start (or another server).
		if err := d.outbox.Retry(save, row.ID, now, cause.Error(), to, string(tmpl)); err != nil {
			d.logger.Warn("e-mail outbox not updated", "outbox_id", row.ID, "error", err)
		}
		return cause
	}
	next := now.Add(d.retryDelay(row.Attempts))
	if errors.Is(cause, ErrPermanent) || next.After(row.Deadline) {
		reason := cause.Error()
		if !errors.Is(cause, ErrPermanent) {
			reason = fmt.Sprintf("gave up after %d attempts: %s", row.Attempts, reason)
		}
		if err := d.outbox.End(save, row.ID, domain.OutboxFailed, reason, to, string(tmpl)); err != nil {
			d.logger.Warn("e-mail outbox not updated", "outbox_id", row.ID, "error", err)
		}
		d.logger.Error("e-mail not sent", "kind", e.Kind, "user_id", e.UserID, "outbox_id", row.ID,
			"attempts", row.Attempts, "error", cause)
		d.writeAudit(save, e, to, tmpl, row.Attempts, cause)
		return cause
	}
	if err := d.outbox.Retry(save, row.ID, next, cause.Error(), to, string(tmpl)); err != nil {
		d.logger.Warn("e-mail outbox not updated", "outbox_id", row.ID, "error", err)
	}
	d.logger.Warn("e-mail not sent, will try again", "kind", e.Kind, "user_id", e.UserID, "outbox_id", row.ID,
		"attempts", row.Attempts, "next_attempt_at", next.UTC().Format(time.RFC3339), "error", cause)
	return cause
}

func (d *Dispatcher) cancelled(save context.Context, row *domain.OutboxEmail, why error) error {
	if err := d.outbox.End(save, row.ID, domain.OutboxCancelled, why.Error(), "", ""); err != nil {
		d.logger.Warn("e-mail outbox not updated", "outbox_id", row.ID, "error", err)
	}
	d.logger.Info("e-mail cancelled", "kind", row.Kind, "user_id", row.UserID, "outbox_id", row.ID, "reason", why)
	return nil
}

// Process sends the e-mail of an event now, in the caller's goroutine,
// without the outbox (MaxAttempts attempts, RetryDelay apart). It returns
// nil when the e-mail is not wanted (switch off, unknown user).
func (d *Dispatcher) Process(ctx context.Context, e domain.NotificationEvent) error {
	to, tmpl, data, err := d.compose(ctx, e)
	if errors.Is(err, errNotWanted) || errors.Is(err, errNoAccount) || errors.Is(err, errNoAddress) {
		return nil
	}
	if err != nil {
		return err
	}
	attempts, sendErr := d.send(ctx, to, tmpl, data)
	d.writeAudit(ctx, e, to, tmpl, attempts, sendErr)
	return sendErr
}

// compose reads what an e-mail needs: its template, the recipient's address
// and the data of the template, in the recipient's language.
func (d *Dispatcher) compose(ctx context.Context, e domain.NotificationEvent) (string, Template, Data, error) {
	tmpl, ok, err := d.template(ctx, e)
	if err != nil {
		return "", "", Data{}, err
	}
	if !ok {
		return "", "", Data{}, errNotWanted
	}
	user, err := d.users.GetByID(ctx, e.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return "", "", Data{}, errNoAccount
	}
	if err != nil {
		return "", "", Data{}, fmt.Errorf("notify: load user: %w", err)
	}
	if user.Email == "" {
		return "", "", Data{}, errNoAddress
	}
	realm, err := d.realms.GetByID(ctx, e.RealmID)
	if err != nil {
		return "", "", Data{}, fmt.Errorf("notify: load realm: %w", err)
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
	return user.Email, tmpl, data, nil
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
	if d.settings == nil {
		return "", false, nil // defaults: alerts off
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
	if d.audit == nil || (e.QuietAudit && sendErr == nil) {
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
	if e.OperationID != "" {
		details["operation_id"] = e.OperationID
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
	case domain.NotificationPasswordReset, domain.NotificationPasswordResetRequired:
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
	case domain.NotificationEmailVerification:
		out.VerifyURL = d.link(realm, "/auth/verify-email") + "#token=" + url.QueryEscape(e.ResetToken)
		out.ExpiresIn = humanDuration(loc, e.ExpiresAt.Sub(e.OccurredAt))
	case domain.NotificationAdminRecovery:
		out.RecoveryKind = knownText(loc, recoveryKinds, e.RecoveryKind)
		out.RecoveryActor = e.RecoveryActor
		out.RecoveryAccount = e.RecoveryAccount
	case domain.NotificationUserImportFinished:
		out.ImportRealm = e.ImportRealm
		out.ImportFile = e.ImportFile
		out.ImportTotal = e.ImportTotal
		out.ImportCreated = e.ImportCreated
		out.ImportFailed = e.ImportFailed
		out.ImportNotDone = e.ImportTotal - e.ImportCreated - e.ImportFailed
		out.ImportInterrupted = e.ImportInterrupted
		out.ImportURL = e.ImportURL
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
		i18n.M("email.recovery.kind.ip_allowlist_cleared", "the IP allowlist of the master realm emptied"),
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
