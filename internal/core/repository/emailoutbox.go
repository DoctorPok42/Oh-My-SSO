package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// EmailOutboxRepository stores the e-mails waiting to leave and what became
// of them (notify.Dispatcher). Several dispatchers, in several processes,
// work on the same rows: Claim hands each due e-mail to one of them at a
// time.
type EmailOutboxRepository interface {
	// Create stores a new pending e-mail. e.ID is set by the caller (the
	// link is sealed with it); the status, attempts and dates of e are used.
	Create(ctx context.Context, e *domain.OutboxEmail) error
	// Claim takes one pending e-mail that is due (next attempt reached, no
	// dispatcher holding it) and holds it until now+lease: its attempts
	// grow by one. id "": the most overdue one; otherwise that one only.
	// ErrNotFound when there is none. Rows another dispatcher is claiming at
	// the same moment are skipped, never waited for.
	Claim(ctx context.Context, id string, now time.Time, lease time.Duration) (*domain.OutboxEmail, error)
	// Sent records that the e-mail left, to recipient.
	Sent(ctx context.Context, id, recipient, template string, at time.Time) error
	// Retry puts the e-mail back in the queue for next, with the error of
	// the attempt (recipient and template: "" when not known yet).
	Retry(ctx context.Context, id string, next time.Time, lastError, recipient, template string) error
	// End gives up: status OutboxFailed or OutboxCancelled, with why.
	End(ctx context.Context, id string, status domain.OutboxStatus, reason, recipient, template string) error
	// Requeue sends a failed or pending e-mail again at once, until
	// deadline. It reports false when the e-mail is neither (sent,
	// cancelled, or another dispatcher holds it right now).
	Requeue(ctx context.Context, id string, now, deadline time.Time) (bool, error)
	Get(ctx context.Context, id string) (*domain.OutboxEmail, error)
	// ListByUser: the account's latest e-mails, newest first.
	ListByUser(ctx context.Context, userID string, limit int) ([]*domain.OutboxEmail, error)
	// LatestByUsers: for each account, its latest e-mail of this kind asked
	// for at or after since (an import's invitations).
	LatestByUsers(ctx context.Context, userIDs []string, kind domain.NotificationKind, since time.Time) (map[string]*domain.OutboxEmail, error)
}

// EmailVerificationRepository stores the links of the address verification
// e-mails.
type EmailVerificationRepository interface {
	Create(ctx context.Context, t *domain.EmailVerificationToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.EmailVerificationToken, error)
	// LatestCreatedAt: when the account's last link was made (zero: never).
	LatestCreatedAt(ctx context.Context, userID string) (time.Time, error)
	// Consume marks the link used, once: false when it already was.
	Consume(ctx context.Context, id string, at time.Time) (bool, error)
	// DeleteUnusedByUser cancels the account's links not used yet.
	DeleteUnusedByUser(ctx context.Context, userID string) (int, error)
	// MarkEmailVerified sets users.email_verified_at to at if the account's
	// address still is email and is not verified yet, in one statement (an
	// address changed in between is not marked). It reports whether it did.
	MarkEmailVerified(ctx context.Context, userID, email string, at time.Time) (bool, error)
}
