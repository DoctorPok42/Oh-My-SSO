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
	LockoutThreshold            int
	LockoutDurationMinutes      int
	IPAllowlist                 []string
	MFARequiredGlobally         bool
	NotificationEmailEnabled    bool
	KeyRotationGraceHours       int
	MFAStepUpMaxAgeMinutes      int
	PasswordResetTTLMinutes     int  // Step 12
	SuspiciousLoginEmailEnabled bool // Step 12
	UpdatedAt                   time.Time
	UpdatedBy                   string
}
