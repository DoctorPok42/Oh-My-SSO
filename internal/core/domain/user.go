package domain

import (
	"strings"
	"time"
)

// NormalizeIdentifier is the form in which usernames and e-mail addresses
// are stored and looked up: trimmed, in lower case. "Alice@Example.com" and
// "alice@example.com" are one account, whatever the case typed to sign in.
func NormalizeIdentifier(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

type UserStatus string

const (
	UserActive    UserStatus = "active"
	UserInactive  UserStatus = "inactive"
	UserSuspended UserStatus = "suspended"
)

type User struct {
	ID           string
	RealmID      string
	Username     string
	PasswordHash string
	Email        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
	Status       UserStatus
	LastLoginAt  *time.Time
	Profile      map[string]interface{}
	Lockout      LockoutState
	// MustChangePassword: an administrator forced a password reset. Signing
	// in with the password is refused until the password changes.
	MustChangePassword bool
}
