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
	SuspiciousLoginEmailEnabled bool
	MFATrustedDeviceEnabled     bool
	MFATrustedDeviceDays        int
	UpdatedAt                   time.Time
	UpdatedBy                   string
}
