package domain

import "time"

type SessionStatus string

const (
	SessionActive  SessionStatus = "active"
	SessionExpired SessionStatus = "expired"
	SessionRevoked SessionStatus = "revoked"
)

type SessionRevokedReason string

const (
	SessionRevokedUserLogout     SessionRevokedReason = "user_logout"
	SessionRevokedAdminRevoked   SessionRevokedReason = "admin_revoked"
	SessionRevokedSecurityPolicy SessionRevokedReason = "security_policy"
	SessionRevokedExpired        SessionRevokedReason = "expired"
	SessionRevokedPasswordReset  SessionRevokedReason = "password_reset"
	SessionRevokedMFAReset       SessionRevokedReason = "mfa_reset"
)

type Session struct {
	ID                string
	RealmID           string
	UserID            string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	LastActivityAt    time.Time
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	MFAVerified       bool
	MFAMethodType     string
	AuthMethod        string
	Status            SessionStatus
	RevokedReason     SessionRevokedReason
	TokenHash         string
}
