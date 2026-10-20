package domain

import "time"

// LockoutState is the account lockout bookkeeping of one login identity
// (Step 12): a known user (columns of the users table) or an identifier
// that matches no account (kept in Valkey, so that both behave the same and
// a lock never reveals whether an account exists).
//
// Zero times mean "never".
type LockoutState struct {
	// FailedCount: wrong passwords in a row inside the observation window.
	FailedCount  int
	LastFailedAt time.Time
	// LockedUntil: sign-in refused until this time (zero = not locked).
	LockedUntil time.Time
	// LockCount: locks in a row, used to double the next lock duration.
	LockCount    int
	LastLockedAt time.Time
}

// IsZero tells whether there is nothing to remember (no failure, no lock).
func (s LockoutState) IsZero() bool {
	return s.FailedCount == 0 && s.LastFailedAt.IsZero() && s.LockedUntil.IsZero() &&
		s.LockCount == 0 && s.LastLockedAt.IsZero()
}

// LockedAt tells whether sign-in is refused at time now.
func (s LockoutState) LockedAt(now time.Time) bool {
	return !s.LockedUntil.IsZero() && now.Before(s.LockedUntil)
}
