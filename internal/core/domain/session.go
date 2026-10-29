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
	// Another account signed in in the same browser ("Use another account").
	SessionRevokedAccountSwitch SessionRevokedReason = "account_switch"
	// An administrator's timeout on the user, one of their groups or the
	// client started.
	SessionRevokedTimeout SessionRevokedReason = "timeout"
)

// Authentication Method Reference values (RFC 8176 §2), stored as-is in
// Session.AuthMethod so the OIDC "amr" claim needs no translation.
const (
	AuthMethodPassword    = "pwd" // password
	AuthMethodOTP         = "otp" // one-time password (TOTP, backup codes)
	AuthMethodHardwareKey = "hwk" // proof of possession of a hardware-protected key
	AuthMethodSoftwareKey = "swk" // proof of possession of a software-protected key
	AuthMethodMFA         = "mfa" // more than one factor was used
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
	MFAVerifiedAt     time.Time // last second-factor verification (login or step-up); zero if never
	AuthMethod        string
	Status            SessionStatus
	RevokedReason     SessionRevokedReason
	TokenHash         string
	// RememberMe: the user ticked "Keep me signed in". The session follows
	// the realm's remember-me durations and its cookie is persistent.
	RememberMe bool
	// TrustedDevice: the second factor was skipped because the device is
	// trusted ("Don't ask again on this device"). Never MFA-verified.
	TrustedDevice bool
}
