package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Address verification (audit B-13): an e-mail with a single-use link, sent
// to the account's address; opening it marks the address verified
// (users.email_verified_at, the OIDC claim email_verified). The link is
// bound to the address it went to: if the address changes in between, it
// proves nothing and is refused. A reset or activation link e-mailed to the
// address verifies it too (PasswordResetService.ResetPassword).
const (
	// EmailVerificationTTL: how long a verification link works.
	EmailVerificationTTL = 24 * time.Hour
	// emailVerificationCooldown: one e-mail a minute per account at most,
	// whoever asks.
	emailVerificationCooldown = time.Minute
)

var (
	// ErrEmailAlreadyVerified: nothing to do.
	ErrEmailAlreadyVerified = errors.New("service: the e-mail address is already verified")
	// ErrEmailVerificationTooSoon: a link was sent less than a minute ago.
	ErrEmailVerificationTooSoon = errors.New("service: a verification e-mail was sent less than a minute ago")
	// ErrEmailVerificationUnavailable: e-mails cannot leave (no SMTP), or
	// this one could not be queued.
	ErrEmailVerificationUnavailable = errors.New("service: the verification e-mail cannot be sent")
	// ErrEmailVerificationInvalid covers unknown, used, expired links, and
	// links to an address the account no longer has.
	ErrEmailVerificationInvalid = errors.New("service: the verification link is invalid or has expired")
)

// EmailVerificationDeps groups the dependencies of
// NewEmailVerificationService.
type EmailVerificationDeps struct {
	Tx       repository.Transactor // required (repository.NoTransaction{} in memory)
	Users    repository.UserRepository
	Links    repository.EmailVerificationRepository
	Notifier Notifier // nil or NopNotifier: no e-mail, Send refuses
	Audit    repository.AuditLogRepository
	Now      func() time.Time
	Logger   *slog.Logger
}

// EmailVerificationService sends and checks the verification links.
type EmailVerificationService struct {
	d EmailVerificationDeps
}

func NewEmailVerificationService(d EmailVerificationDeps) *EmailVerificationService {
	if d.Tx == nil {
		panic("service: EmailVerificationDeps.Tx is required (repository.NoTransaction{} for in-memory stores)")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &EmailVerificationService{d: d}
}

// Enabled tells whether verification e-mails can leave.
func (s *EmailVerificationService) Enabled() bool {
	if s == nil || s.d.Notifier == nil {
		return false
	}
	_, nop := s.d.Notifier.(NopNotifier)
	return !nop
}

// VerificationRequester is who asks for a verification e-mail: the user in
// the account console, or an administrator (ActorType admin, ActorID their
// account).
type VerificationRequester struct {
	ActorType domain.AuditActorType
	ActorID   string
	IPAddress string
	UserAgent string
	// Silent: the caller writes the audit entry (an administrator's, with
	// their realm and name).
	Silent bool
}

// Send e-mails a new verification link to the account's address (the
// previous links stop working) and returns when it expires.
func (s *EmailVerificationService) Send(ctx context.Context, user *domain.User, by VerificationRequester) (time.Time, error) {
	if !s.Enabled() {
		return time.Time{}, ErrEmailVerificationUnavailable
	}
	if user.EmailVerifiedAt != nil {
		return time.Time{}, ErrEmailAlreadyVerified
	}
	if user.Email == "" || user.Status != domain.UserActive {
		return time.Time{}, ErrEmailVerificationUnavailable
	}
	now := s.d.Now()
	last, err := s.d.Links.LatestCreatedAt(ctx, user.ID)
	if err != nil {
		return time.Time{}, fmt.Errorf("email verification: last link: %w", err)
	}
	if !last.IsZero() && now.Sub(last) < emailVerificationCooldown {
		return time.Time{}, ErrEmailVerificationTooSoon
	}

	raw, hash := newResetToken()
	expires := now.Add(EmailVerificationTTL)
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.d.Links.DeleteUnusedByUser(ctx, user.ID); err != nil {
			return fmt.Errorf("email verification: cancel previous links: %w", err)
		}
		if err := s.d.Links.Create(ctx, &domain.EmailVerificationToken{
			UserID: user.ID, Email: user.Email, TokenHash: hash, ExpiresAt: expires, CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("email verification: store link: %w", err)
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	event := domain.NotificationEvent{
		Kind: domain.NotificationEmailVerification, RealmID: user.RealmID, UserID: user.ID,
		OccurredAt: now, IPAddress: by.IPAddress, UserAgent: by.UserAgent, ResetToken: raw, ExpiresAt: expires,
	}
	if q, ok := s.d.Notifier.(QueueNotifier); ok {
		if err := q.NotifyWait(ctx, event); err != nil {
			s.d.Logger.ErrorContext(ctx, "email verification: e-mail not queued", "user_id", user.ID, "error", err)
			return time.Time{}, ErrEmailVerificationUnavailable
		}
	} else {
		s.d.Notifier.Notify(ctx, event)
	}
	s.audit(ctx, user, by, audit.UserEmailVerificationSent, map[string]interface{}{
		"email": user.Email, "expires_at": expires.UTC().Format(time.RFC3339),
	})
	return expires, nil
}

// Verify uses a link: the address is verified if it still is the account's.
// The link must belong to realmID. It returns the account.
func (s *EmailVerificationService) Verify(ctx context.Context, realmID, token, ip, userAgent string) (*domain.User, error) {
	if token == "" {
		return nil, ErrEmailVerificationInvalid
	}
	tok, err := s.d.Links.GetByTokenHash(ctx, HashResetToken(token))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrEmailVerificationInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("email verification: lookup link: %w", err)
	}
	now := s.d.Now()
	if tok.UsedAt != nil || !now.Before(tok.ExpiresAt) {
		return nil, ErrEmailVerificationInvalid
	}
	user, err := s.d.Users.GetByID(ctx, tok.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrEmailVerificationInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("email verification: load user: %w", err)
	}
	// A link of realm A does not work on the pages of realm B, and a link
	// sent to an address the account no longer has proves nothing.
	if user.RealmID != realmID || user.Status != domain.UserActive || user.Email != tok.Email {
		return nil, ErrEmailVerificationInvalid
	}
	err = s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		used, err := s.d.Links.Consume(ctx, tok.ID, now)
		if err != nil {
			return fmt.Errorf("email verification: use link: %w", err)
		}
		if !used {
			return ErrEmailVerificationInvalid // another request used it a moment ago
		}
		// false: already verified, or the address changed a moment ago
		// (then the account stays unverified).
		if _, err := s.d.Links.MarkEmailVerified(ctx, user.ID, tok.Email, now); err != nil {
			return fmt.Errorf("email verification: mark verified: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	fresh, err := s.d.Users.GetByID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("email verification: reload user: %w", err)
	}
	if fresh.EmailVerifiedAt == nil {
		return nil, ErrEmailVerificationInvalid
	}
	s.audit(ctx, fresh, VerificationRequester{ActorType: domain.AuditActorUser, ActorID: user.ID, IPAddress: ip, UserAgent: userAgent},
		audit.UserEmailVerified, map[string]interface{}{"email": tok.Email})
	return fresh, nil
}

func (s *EmailVerificationService) audit(ctx context.Context, user *domain.User, by VerificationRequester, action string, details map[string]interface{}) {
	if s.d.Audit == nil || by.Silent {
		return
	}
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      user.RealmID,
		UserID:       by.ActorID,
		ActorType:    by.ActorType,
		TargetUserID: user.ID,
		Action:       action,
		ResourceType: "User",
		ResourceID:   user.ID,
		IPAddress:    by.IPAddress,
		UserAgent:    by.UserAgent,
		Level:        domain.AuditLogInfo,
		Status:       domain.AuditLogSuccess,
		Details:      details,
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "email verification: audit failed", "user_id", user.ID, "error", err)
	}
}
