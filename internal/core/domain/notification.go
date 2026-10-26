package domain

import "time"

type NotificationKind string

const (
	// Password reset flow. Sent whenever e-mail is configured: a realm
	// cannot switch off "forgot password".
	NotificationPasswordReset   NotificationKind = "password_reset"
	NotificationPasswordChanged NotificationKind = "password_changed"

	// Security alerts. Sent only when the realm's notification_email_enabled
	// is on.
	NotificationNewDeviceLogin         NotificationKind = "new_device_login"
	NotificationMfaMethodAdded         NotificationKind = "mfa_method_added"
	NotificationMfaMethodRemoved       NotificationKind = "mfa_method_removed"
	NotificationMfaReset               NotificationKind = "mfa_reset"
	NotificationBackupCodesRegenerated NotificationKind = "backup_codes_regenerated"
	NotificationAccountLocked          NotificationKind = "account_locked"
	// NotificationSuspiciousLogin also needs suspicious_login_email_enabled.
	NotificationSuspiciousLogin NotificationKind = "suspicious_login"
	NotificationAppConnected NotificationKind = "app_connected"

	NotificationAccountInvite NotificationKind = "account_invite"
	NotificationAdminRecovery NotificationKind = "admin_recovery"
)

// IsSecurityAlert tells whether the realm's notification_email_enabled
// switch applies to this kind.
func (k NotificationKind) IsSecurityAlert() bool {
	switch k {
	case NotificationPasswordReset, NotificationPasswordChanged,
		NotificationAccountInvite, NotificationAdminRecovery:
		return false
	default:
		return true
	}
}

// Reasons that make a successful sign-in "suspicious" (AuditLog level
// suspicious, NotificationEvent.SuspiciousReasons).
const (
	SuspiciousNewCountry          = "new_country"            // country never seen for this user
	SuspiciousUnusualHour         = "unusual_hour"           // far from the user's usual sign-in hours
	SuspiciousNewNetworkAndDevice = "new_network_and_device" // unknown browser on an unknown network
)

// NotificationEvent is what the core hands to the notification dispatcher.
// Only the fields that make sense for its Kind are set.
type NotificationEvent struct {
	Kind       NotificationKind
	RealmID    string
	UserID     string
	OccurredAt time.Time
	IPAddress  string // where the action came from, when known
	UserAgent  string

	// password_reset: the raw token. It only ever exists in memory and in
	// the e-mail; the database keeps its SHA-256.
	ResetToken string
	// password_reset: when the link expires. account_locked: when the lock ends.
	ExpiresAt time.Time

	// mfa_method_added / mfa_method_removed.
	MfaMethodType MfaMethodType
	MfaMethodName string

	// account_locked: wrong passwords that caused the lock.
	FailedAttempts int

	// new_device_login / suspicious_login.
	SessionID   string
	CountryCode string // ISO 3166-1 alpha-2, "" when unknown
	CountryName string
	// suspicious_login only.
	SuspiciousReasons []string
	// suspicious_login: the browser was unknown too. When the realm does not
	// send suspicious-login e-mails, the "new device" e-mail goes instead.
	NewDevice bool

	// app_connected: the application and what it can now receive, in the
	// words of the consent screen. AccessAdded: it already had access to
	// something, these items come on top.
	ClientName  string
	Access      []string
	AccessAdded bool

	RecoveryKind    string
	RecoveryActor   string
	RecoveryAccount string
}
