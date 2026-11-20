package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type InstanceSettingsRepository interface {
	Create(ctx context.Context, p CreateInstanceSettingsParams) (*domain.InstanceSettings, error)
	GetByRealmID(ctx context.Context, realmID string) (*domain.InstanceSettings, error)
	Update(ctx context.Context, id string, p UpdateInstanceSettingsParams) (*domain.InstanceSettings, error)
	Delete(ctx context.Context, id string) error
	// ClaimKeyRotation reserves the automatic key rotation of a realm until
	// `until`. It reports false when another instance holds the claim (or the
	// realm has no settings): only the instance that gets true rotates.
	ClaimKeyRotation(ctx context.Context, realmID string, now, until time.Time) (bool, error)
}

type CreateInstanceSettingsParams struct {
	RealmID string
}

type UpdateInstanceSettingsParams struct {
	ManagedBy                   *domain.InstanceSettingsManagedBy
	MinPasswordLength           *int
	PasswordExpiryDays          *int
	PasswordBreachCheckEnabled  *bool
	SessionIdleMinutes          *int
	SessionMaxHours             *int
	RememberMeEnabled           *bool
	RememberMeIdleDays          *int
	RememberMeMaxDays           *int
	LockoutThreshold            *int
	LockoutDurationMinutes      *int
	IPAllowlist                 []string
	MFARequiredGlobally         *bool
	NotificationEmailEnabled    *bool
	KeyRotationGraceHours       *int
	KeyRotationIntervalDays     *int
	MFAStepUpMaxAgeMinutes      *int
	PasswordResetTTLMinutes     *int
	InviteTTLHours              *int
	SuspiciousLoginEmailEnabled *bool
	MFATrustedDeviceEnabled     *bool
	MFATrustedDeviceDays        *int
	DefaultLocale               *string
	MailFromName                *string
	MailFromAddress             *string
	MailReplyTo                 *string
	MailLogoURL                 *string
	BulkLimit                   *int
	ExpiredDataRetentionDays    *int
	AuditLogRetentionDays       *int
	UpdatedBy                   *string
}
