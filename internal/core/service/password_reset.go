package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Password reset (Step 12), following the OWASP Forgot Password Cheat Sheet:
// https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
//
//	POST /auth/forgot-password {identifier}
//	  └─► always "202 Accepted", same body, same time: the answer never
//	      says whether the account exists. In the background:
//	      RequestReset ─► random token (256 bits), SHA-256 stored,
//	                      single use, expires (realm's password_reset_ttl_minutes)
//	                  ─► e-mail with  PUBLIC_URL/r/<realm>/auth/reset-password#token=...
//
//	POST /auth/reset-password {token, password}
//	  └─► ResetPassword ─► token valid? policy OK? ─► new Argon2id hash
//	                    ─► ALL sessions revoked (reason "password_reset")
//	                    ─► lockout cleared, other links cancelled
//	                    ─► "password changed" e-mail
//
// After a reset the user signs in again, second factor included: access to
// a mailbox must never be enough to get past MFA.

var (
	// ErrResetTokenInvalid covers unknown, expired and already used tokens,
	// and inactive accounts: the page only needs "ask for a new link".
	ErrResetTokenInvalid = errors.New("service: password reset link is invalid or has expired")
)

const resetTokenBytes = 32 // 256 bits, the same strength as a session token

// PasswordResetService runs both halves of the flow.
type PasswordResetService struct {
	users    repository.UserRepository
	tokens   repository.PasswordResetTokenRepository
	sessions *SessionService
	policy   *PasswordPolicyService
	lockout  *LockoutService // optional: a reset also unlocks the account
	notifier Notifier
	audit    repository.AuditLogRepository // optional
	settings *settingsCache
	now      func() time.Time
	logger   *slog.Logger

	// async limits the background requests running at once (RequestResetAsync).
	async chan struct{}
}

// PasswordResetDeps groups the dependencies of NewPasswordResetService.
type PasswordResetDeps struct {
	Users    repository.UserRepository
	Tokens   repository.PasswordResetTokenRepository
	Sessions *SessionService
	Policy   *PasswordPolicyService
	Settings repository.InstanceSettingsRepository // password_reset_ttl_minutes
	Lockout  *LockoutService                       // optional
	Notifier Notifier                              // nil: no e-mail (the link is lost)
	Audit    repository.AuditLogRepository         // optional
	Now      func() time.Time                      // optional (tests)
	Logger   *slog.Logger                          // optional
}

func NewPasswordResetService(d PasswordResetDeps) *PasswordResetService {
	s := &PasswordResetService{
		users:    d.Users,
		tokens:   d.Tokens,
		sessions: d.Sessions,
		policy:   d.Policy,
		lockout:  d.Lockout,
		notifier: d.Notifier,
		audit:    d.Audit,
		now:      d.Now,
		logger:   d.Logger,
		async:    make(chan struct{}, 32),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.notifier == nil {
		s.notifier = NopNotifier{}
	}
	if s.policy == nil {
		s.policy = NewPasswordPolicyService(d.Settings)
	}
	s.settings = newSettingsCache(d.Settings, s.logger)
	return s
}

// RequestResetInput is a "forgot password" form.
type RequestResetInput struct {
	RealmID    string
	Identifier string // username or e-mail, like the login form
	IPAddress  string
	UserAgent  string
}

// RequestResetAsync starts RequestReset in the background and returns at
// once. The HTTP handler uses it so that its answer takes the same time
// whether the account exists or not. When too many requests are already
// running the request is dropped (logged): the user can ask again, and the
// HTTP answer is the same anyway.
func (s *PasswordResetService) RequestResetAsync(ctx context.Context, in RequestResetInput) {
	ctx = context.WithoutCancel(ctx) // the HTTP request ends before we do
	select {
	case s.async <- struct{}{}:
	default:
		s.logger.WarnContext(ctx, "password reset: too many requests in progress, request dropped", "realm_id", in.RealmID)
		return
	}
	go func() {
		defer func() { <-s.async }()
		if err := s.RequestReset(ctx, in); err != nil {
			s.logger.ErrorContext(ctx, "password reset request failed", "realm_id", in.RealmID, "error", err)
		}
	}()
}

// RequestReset creates a reset token and asks for the e-mail. Unknown
// identifiers, inactive accounts and accounts without a local password
// (federated only) end silently with nil: nothing is sent.
func (s *PasswordResetService) RequestReset(ctx context.Context, in RequestResetInput) error {
	user, err := findUserByIdentifier(ctx, s.users, in.RealmID, in.Identifier)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("password reset: lookup user: %w", err)
	}
	if user.Status != domain.UserActive || user.PasswordHash == "" {
		return nil
	}

	// One valid link at a time: asking again cancels the previous links.
	if _, err := s.tokens.DeleteUnusedByUser(ctx, user.ID); err != nil {
		return fmt.Errorf("password reset: cancel previous links: %w", err)
	}

	raw, hash := newResetToken()
	now := s.now()
	expires := now.Add(s.ttl(ctx, user.RealmID))
	if _, err := s.tokens.Create(ctx, repository.CreatePasswordResetTokenParams{
		UserID:      user.ID,
		TokenHash:   hash,
		ExpiresAt:   expires,
		RequestedIP: in.IPAddress,
	}); err != nil {
		return fmt.Errorf("password reset: store token: %w", err)
	}

	s.auditEvent(ctx, user, "password_reset_requested", in.IPAddress, in.UserAgent, domain.AuditLogInfo, map[string]interface{}{
		"expires_at": expires.UTC().Format(time.RFC3339),
	})
	s.notifier.Notify(ctx, domain.NotificationEvent{
		Kind:       domain.NotificationPasswordReset,
		RealmID:    user.RealmID,
		UserID:     user.ID,
		OccurredAt: now,
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
		ResetToken: raw,
		ExpiresAt:  expires,
	})
	return nil
}

// IssueActivationToken (Step 14) creates a one-time "choose your password"
// token for an account an admin (or `idp-admin bootstrap`) just created. It
// is a reset token like any other: same table, same page, same rules. It
// works once, expires after ttl, and cancels the user's earlier unused
// links. It sends nothing: the caller e-mails the link (invitation) or
// shows it once to whoever created the account.
//
// issuedBy is written to the audit log ("user:<admin id>", "cli:root@host").
func (s *PasswordResetService) IssueActivationToken(ctx context.Context, user *domain.User, ttl time.Duration, issuedBy string) (string, time.Time, error) {
	if ttl <= 0 {
		return "", time.Time{}, errors.New("password reset: activation link lifetime must be positive")
	}
	if _, err := s.tokens.DeleteUnusedByUser(ctx, user.ID); err != nil {
		return "", time.Time{}, fmt.Errorf("activation link: cancel previous links: %w", err)
	}
	raw, hash := newResetToken()
	expires := s.now().Add(ttl)
	if _, err := s.tokens.Create(ctx, repository.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("activation link: store token: %w", err)
	}
	s.auditEvent(ctx, user, "activation_link_issued", "", "", domain.AuditLogInfo, map[string]interface{}{
		"issued_by":  issuedBy,
		"expires_at": expires.UTC().Format(time.RFC3339),
	})
	return raw, expires, nil
}

// ResetPasswordInput is the "choose a new password" form.
type ResetPasswordInput struct {
	RealmID     string
	Token       string // from the link
	NewPassword string
	IPAddress   string
	UserAgent   string
}

// ResetPassword checks the token and sets the new password. Errors:
// ErrResetTokenInvalid, or a *PasswordPolicyError (the token is NOT used
// up then, so the user can try another password with the same link).
func (s *PasswordResetService) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if in.Token == "" {
		return ErrResetTokenInvalid
	}
	tok, err := s.tokens.GetByTokenHash(ctx, HashResetToken(in.Token))
	if errors.Is(err, repository.ErrNotFound) {
		return ErrResetTokenInvalid
	}
	if err != nil {
		return fmt.Errorf("password reset: lookup token: %w", err)
	}
	now := s.now()
	if tok.Used || !now.Before(tok.ExpiresAt) {
		return ErrResetTokenInvalid
	}
	user, err := s.users.GetByID(ctx, tok.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrResetTokenInvalid
	}
	if err != nil {
		return fmt.Errorf("password reset: load user: %w", err)
	}
	// A link of realm A must not work on the pages of realm B.
	if user.RealmID != in.RealmID || user.Status != domain.UserActive {
		return ErrResetTokenInvalid
	}

	if err := s.policy.Validate(ctx, user.RealmID, in.NewPassword, user); err != nil {
		return err
	}
	// Hash before using up the token: if hashing failed, the link would be
	// lost for nothing.
	hash, err := HashPassword(in.NewPassword)
	if err != nil {
		return fmt.Errorf("password reset: %w", err)
	}

	consumed, err := s.tokens.ConsumeIfUnused(ctx, tok.ID, now)
	if err != nil {
		return fmt.Errorf("password reset: use token: %w", err)
	}
	if !consumed {
		return ErrResetTokenInvalid // another request used it a moment ago
	}

	if _, err := s.users.Update(ctx, user.ID, repository.UpdateUserParams{PasswordHash: &hash}); err != nil {
		return fmt.Errorf("password reset: update password: %w", err)
	}

	// Changing the password is a strong signal: whoever had a session (maybe
	// the person who stole the old password) is signed out everywhere, and
	// the tokens issued to applications for those sessions die with them.
	if err := s.sessions.RevokeAllForUser(ctx, user.ID, domain.SessionRevokedPasswordReset); err != nil {
		return fmt.Errorf("password reset: revoke sessions: %w", err)
	}
	if _, err := s.tokens.DeleteUnusedByUser(ctx, user.ID); err != nil {
		s.logger.WarnContext(ctx, "password reset: cannot cancel other links", "user_id", user.ID, "error", err)
	}
	if s.lockout != nil {
		if err := s.lockout.Unlock(ctx, user); err != nil {
			s.logger.WarnContext(ctx, "password reset: cannot clear lockout", "user_id", user.ID, "error", err)
		}
	}

	s.auditEvent(ctx, user, "password_reset", in.IPAddress, in.UserAgent, domain.AuditLogWarning, map[string]interface{}{
		"sessions_revoked": true,
	})
	s.notifier.Notify(ctx, domain.NotificationEvent{
		Kind:       domain.NotificationPasswordChanged,
		RealmID:    user.RealmID,
		UserID:     user.ID,
		OccurredAt: now,
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
	})
	return nil
}

// MinPasswordLength is shown on the reset page.
func (s *PasswordResetService) MinPasswordLength(ctx context.Context, realmID string) int {
	return s.policy.MinLength(ctx, realmID)
}

func (s *PasswordResetService) ttl(ctx context.Context, realmID string) time.Duration {
	m := s.settings.get(ctx, realmID).PasswordResetTTLMinutes
	if m <= 0 {
		m = defaultPasswordResetTTLMinutes
	}
	return time.Duration(m) * time.Minute
}

func (s *PasswordResetService) auditEvent(ctx context.Context, user *domain.User, action, ip, ua string, level domain.AuditLogLevel, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      user.RealmID,
		UserID:       user.ID,
		Action:       action,
		ResourceType: "User",
		ResourceID:   user.ID,
		IPAddress:    ip,
		UserAgent:    ua,
		Level:        level,
		Status:       domain.AuditLogSuccess,
		Details:      details,
	})
}

// newResetToken returns a random URL-safe token and its stored hash.
func newResetToken() (raw, hash string) {
	b := make([]byte, resetTokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashResetToken(raw)
}

// HashResetToken is what the database keeps of a reset token. A fast hash
// is enough: the token is 256 random bits, not something a human chose.
func HashResetToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// findUserByIdentifier looks a user up by username, then by e-mail (same
// rule as the login form).
func findUserByIdentifier(ctx context.Context, users repository.UserRepository, realmID, identifier string) (*domain.User, error) {
	if identifier == "" {
		return nil, repository.ErrNotFound
	}
	u, err := users.GetByRealmAndUsername(ctx, realmID, identifier)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	return users.GetByRealmAndEmail(ctx, realmID, identifier)
}
