package repository

import (
	"context"

	"sso.internal/sso/internal/core/domain"
)

type InstanceSettingsRepository interface {
	Create(ctx context.Context, p CreateInstanceSettingsParams) (*domain.InstanceSettings, error)
	GetByRealmID(ctx context.Context, realmID string) (*domain.InstanceSettings, error)
	Update(ctx context.Context, id string, p UpdateInstanceSettingsParams) (*domain.InstanceSettings, error)
	Delete(ctx context.Context, id string) error
}

type CreateInstanceSettingsParams struct {
	RealmID string
}

type UpdateInstanceSettingsParams struct {
	ManagedBy                *domain.InstanceSettingsManagedBy
	MinPasswordLength        *int
	PasswordExpiryDays       *int
	SessionIdleMinutes       *int
	SessionMaxHours          *int
	LockoutThreshold         *int
	LockoutDurationMinutes   *int
	IPAllowlist              []string
	MFARequiredGlobally      *bool
	NotificationEmailEnabled *bool
	UpdatedBy                *string
}
