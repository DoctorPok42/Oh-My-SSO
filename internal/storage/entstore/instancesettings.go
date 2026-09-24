package entstore

import (
	"context"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/instancesettings"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entInstanceSettingsRepository struct {
	client *ent.Client
}

func NewInstanceSettingsRepository(client *ent.Client) repository.InstanceSettingsRepository {
	return &entInstanceSettingsRepository{client: client}
}

func (r *entInstanceSettingsRepository) Create(ctx context.Context, p repository.CreateInstanceSettingsParams) (*domain.InstanceSettings, error) {
	e, err := r.client.InstanceSettings.
		Create().
		SetRealmID(p.RealmID).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainInstanceSettings(e), nil
}

func (r *entInstanceSettingsRepository) GetByRealmID(ctx context.Context, realmID string) (*domain.InstanceSettings, error) {
	e, err := r.client.InstanceSettings.
		Query().
		Where(instancesettings.RealmID(realmID)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainInstanceSettings(e), nil
}

func (r *entInstanceSettingsRepository) Update(ctx context.Context, id string, p repository.UpdateInstanceSettingsParams) (*domain.InstanceSettings, error) {
	builder := r.client.InstanceSettings.UpdateOneID(id)

	if p.ManagedBy != nil {
		builder = builder.SetManagedBy(entschema.InstanceSettingsManagedBy(*p.ManagedBy))
	}
	builder = builder.
		SetNillableMinPasswordLength(p.MinPasswordLength).
		SetNillablePasswordExpiryDays(p.PasswordExpiryDays).
		SetNillableSessionIdleMinutes(p.SessionIdleMinutes).
		SetNillableSessionMaxHours(p.SessionMaxHours).
		SetNillableLockoutThreshold(p.LockoutThreshold).
		SetNillableLockoutDurationMinutes(p.LockoutDurationMinutes).
		SetNillableMfaRequiredGlobally(p.MFARequiredGlobally).
		SetNillableNotificationEmailEnabled(p.NotificationEmailEnabled).
		SetNillableUpdatedBy(p.UpdatedBy)
	if p.IPAllowlist != nil {
		builder = builder.SetIPAllowlist(p.IPAllowlist)
	}

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainInstanceSettings(e), nil
}

func (r *entInstanceSettingsRepository) Delete(ctx context.Context, id string) error {
	return r.client.InstanceSettings.DeleteOneID(id).Exec(ctx)
}

func toDomainInstanceSettings(e *ent.InstanceSettings) *domain.InstanceSettings {
	return &domain.InstanceSettings{
		ID:                       e.ID,
		RealmID:                  e.RealmID,
		ManagedBy:                domain.InstanceSettingsManagedBy(e.ManagedBy),
		MinPasswordLength:        e.MinPasswordLength,
		PasswordExpiryDays:       e.PasswordExpiryDays,
		SessionIdleMinutes:       e.SessionIdleMinutes,
		SessionMaxHours:          e.SessionMaxHours,
		LockoutThreshold:         e.LockoutThreshold,
		LockoutDurationMinutes:   e.LockoutDurationMinutes,
		IPAllowlist:              e.IPAllowlist,
		MFARequiredGlobally:      e.MfaRequiredGlobally,
		NotificationEmailEnabled: e.NotificationEmailEnabled,
		UpdatedAt:                e.UpdatedAt,
		UpdatedBy:                e.UpdatedBy,
	}
}
