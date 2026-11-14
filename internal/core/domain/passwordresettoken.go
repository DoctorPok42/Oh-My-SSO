package domain

import "time"

type PasswordResetToken struct {
	ID          string
	UserID      string
	TokenHash   string
	ExpiresAt   time.Time
	Used        bool
	UsedAt      time.Time
	RequestedIP string
	// EmailedTo: the address the link was e-mailed to ("" when it was not,
	// e.g. handed over by an administrator). See EmailVerifiedAt.
	EmailedTo string
	CreatedAt time.Time
	UpdatedAt time.Time
}
