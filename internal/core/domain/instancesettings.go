package domain

import "time"

type InstanceSettingsManagedBy string

const (
	InstanceSettingsManagedByUI     InstanceSettingsManagedBy = "ui"
	InstanceSettingsManagedByConfig InstanceSettingsManagedBy = "config"
)

type InstanceSettings struct {
	ID                          string
	RealmID                     string
	ManagedBy                   InstanceSettingsManagedBy
	MinPasswordLength           int
	PasswordExpiryDays          int
	SessionIdleMinutes          int
	SessionMaxHours             int
	RememberMeEnabled           bool
	RememberMeIdleDays          int
	RememberMeMaxDays           int
	LockoutThreshold            int
	LockoutDurationMinutes      int
	IPAllowlist                 []string
	MFARequiredGlobally         bool
	NotificationEmailEnabled    bool
	KeyRotationGraceHours       int
	MFAStepUpMaxAgeMinutes      int
	PasswordResetTTLMinutes     int
	InviteTTLHours              int
	SuspiciousLoginEmailEnabled bool
	MFATrustedDeviceEnabled     bool
	MFATrustedDeviceDays        int
	DefaultLocale               string
	MailFromName                string
	MailFromAddress             string
	MailReplyTo                 string
	MailLogoURL                 string
	BulkLimit                   int
	ExpiredDataRetentionDays    int
	AuditLogRetentionDays       int // 0: the audit log is kept forever
	UpdatedAt                   time.Time
	UpdatedBy                   string
}
