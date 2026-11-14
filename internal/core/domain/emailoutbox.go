package domain

import "time"

// OutboxStatus is where an e-mail of the outbox stands.
type OutboxStatus string

const (
	OutboxPending OutboxStatus = "pending" // waiting for its next attempt
	OutboxSent    OutboxStatus = "sent"
	// OutboxFailed: the mail server refused it for good, or it could not
	// leave before its deadline.
	OutboxFailed OutboxStatus = "failed"
	// OutboxCancelled: no longer worth sending (its link was used or
	// replaced, the account is gone, the realm switched the alert off).
	OutboxCancelled OutboxStatus = "cancelled"
)

// OutboxEmail is one e-mail of the outbox (notify.Dispatcher).
type OutboxEmail struct {
	ID      string
	RealmID string
	UserID  string
	Kind    NotificationKind
	// Event: what the e-mail says, without its link (Event.ResetToken is
	// empty: the link is in SealedToken).
	Event NotificationEvent
	// SealedToken: the link of a reset, activation or verification e-mail,
	// encrypted (envelope) and bound to ID. "" for the other e-mails.
	SealedToken string

	Status        OutboxStatus
	Attempts      int
	NextAttemptAt time.Time
	// Deadline: given up after it (24 h, or sooner when the link expires).
	Deadline  time.Time
	LastError string
	// Recipient, Template: where it went and which e-mail, once tried.
	Recipient string
	Template  string
	CreatedAt time.Time
	UpdatedAt time.Time
	SentAt    *time.Time
}

// OutboxGiveUpAfter: how long the outbox tries to send an e-mail.
const OutboxGiveUpAfter = 24 * time.Hour

// OutboxDeadline is when to give up on the e-mail of e asked for at from:
// giveUp later, or when its link expires if sooner (a dead link is not
// worth sending).
func OutboxDeadline(e NotificationEvent, from time.Time, giveUp time.Duration) time.Time {
	out := from.Add(giveUp)
	if e.Kind.CarriesLink() && !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(out) {
		out = e.ExpiresAt
	}
	return out
}

// CarriesLink tells whether e-mails of this kind hold a single-use link
// (reset, activation, address verification). Such an e-mail is not worth
// sending once its link no longer works.
func (k NotificationKind) CarriesLink() bool {
	switch k {
	case NotificationPasswordReset, NotificationPasswordResetRequired, NotificationAccountInvite,
		NotificationEmailVerification:
		return true
	}
	return false
}

// EmailVerificationToken is the link of an "is this your address?" e-mail,
// bound to the address it was sent to. Only its SHA-256 is stored.
type EmailVerificationToken struct {
	ID        string
	UserID    string
	Email     string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
