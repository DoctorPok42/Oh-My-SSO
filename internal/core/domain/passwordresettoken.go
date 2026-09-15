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
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
