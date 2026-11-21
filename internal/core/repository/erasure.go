package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// Erased replaces a name or an e-mail address of a deleted account in what
// is kept (audit log, reports of bulk actions and imports).
const Erased = "[deleted]"

// ErasureRepository is what deleting an account for good needs beyond the
// rows that go with it (GDPR article 17).
type ErasureRepository interface {
	// ScheduleDeletion sets when the account is deleted for good; nil
	// cancels. ErrNotFound when the account does not exist.
	ScheduleDeletion(ctx context.Context, userID string, at *time.Time) error
	// DeletionDue lists up to limit accounts whose deletion time is before
	// `before`, the earliest first.
	DeletionDue(ctx context.Context, before time.Time, limit int) ([]*domain.User, error)
	// EraseAccount deletes the account (its own rows go with it) and what
	// still identifies it elsewhere, in one transaction: its sign-in attempts
	// are deleted; in the audit log, the addresses and browsers of what it did
	// (or of what was done with its name: sign-ins, lockouts) are cleared, and
	// its names and addresses are replaced with Erased in the details; the
	// same for the reports of bulk actions and user imports. Entries keep
	// their action, date and the account's id: what happened stays visible.
	// dueBy: only if its deletion is still scheduled by then (a cancel since
	// wins); nil: whatever (an administrator deletes it now). It reports
	// false, having changed nothing, when the account is gone or not due.
	EraseAccount(ctx context.Context, u *domain.User, dueBy *time.Time) (bool, error)
}
