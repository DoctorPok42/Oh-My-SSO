package entstore

import (
	"context"
	"time"

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
		SetNillablePasswordHistoryCount(p.PasswordHistoryCount).
		SetNillablePasswordBreachCheckEnabled(p.PasswordBreachCheckEnabled).
		SetNillableAccountDeletionEnabled(p.AccountDeletionEnabled).
		SetNillableEmailChangeAllowed(p.EmailChangeAllowed).
		SetNillableSessionIdleMinutes(p.SessionIdleMinutes).
		SetNillableSessionMaxHours(p.SessionMaxHours).
		SetNillableRememberMeEnabled(p.RememberMeEnabled).
		SetNillableRememberMeIdleDays(p.RememberMeIdleDays).
		SetNillableRememberMeMaxDays(p.RememberMeMaxDays).
		SetNillableLockoutThreshold(p.LockoutThreshold).
		SetNillableLockoutDurationMinutes(p.LockoutDurationMinutes).
		SetNillableMfaRequiredGlobally(p.MFARequiredGlobally).
		SetNillableNotificationEmailEnabled(p.NotificationEmailEnabled).
		SetNillableKeyRotationGraceHours(p.KeyRotationGraceHours).
		SetNillableKeyRotationIntervalDays(p.KeyRotationIntervalDays).
		SetNillableMfaStepUpMaxAgeMinutes(p.MFAStepUpMaxAgeMinutes).
		SetNillablePasswordResetTTLMinutes(p.PasswordResetTTLMinutes).
		SetNillableInviteTTLHours(p.InviteTTLHours).
		SetNillableSuspiciousLoginEmailEnabled(p.SuspiciousLoginEmailEnabled).
		SetNillableMfaTrustedDeviceEnabled(p.MFATrustedDeviceEnabled).
		SetNillableMfaTrustedDeviceDays(p.MFATrustedDeviceDays).
		SetNillableDefaultLocale(p.DefaultLocale).
		SetNillableMailFromName(p.MailFromName).
		SetNillableMailFromAddress(p.MailFromAddress).
		SetNillableMailReplyTo(p.MailReplyTo).
		SetNillableMailLogoURL(p.MailLogoURL).
		SetNillableBulkLimit(p.BulkLimit).
		SetNillableExpiredDataRetentionDays(p.ExpiredDataRetentionDays).
		SetNillableAuditLogRetentionDays(p.AuditLogRetentionDays).
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

// ClaimKeyRotation is one conditional UPDATE: of two instances racing, the
// database lets exactly one change the row.
//
// A claim is not a settings change, so updated_at keeps its value (ent would
// bump it, and the console shows it as "Last change"). The UPDATE also checks
// that updated_at is still the value just read: if an administrator saved the
// settings in between, the claim fails and the next tick tries again.
func (r *entInstanceSettingsRepository) ClaimKeyRotation(ctx context.Context, realmID string, now, until time.Time) (bool, error) {
	cur, err := r.client.InstanceSettings.Query().Where(instancesettings.RealmID(realmID)).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	n, err := r.client.InstanceSettings.Update().
		Where(
			instancesettings.ID(cur.ID),
			instancesettings.UpdatedAt(cur.UpdatedAt),
			instancesettings.Or(
				instancesettings.KeyRotationClaimedUntilIsNil(),
				instancesettings.KeyRotationClaimedUntilLT(now),
			),
		).
		SetKeyRotationClaimedUntil(until).
		SetUpdatedAt(cur.UpdatedAt).
		Save(ctx)
	return n == 1, err
}

func (r *entInstanceSettingsRepository) Delete(ctx context.Context, id string) error {
	return r.client.InstanceSettings.DeleteOneID(id).Exec(ctx)
}

func toDomainInstanceSettings(e *ent.InstanceSettings) *domain.InstanceSettings {
	return &domain.InstanceSettings{
		ID:                          e.ID,
		RealmID:                     e.RealmID,
		ManagedBy:                   domain.InstanceSettingsManagedBy(e.ManagedBy),
		MinPasswordLength:           e.MinPasswordLength,
		PasswordExpiryDays:          e.PasswordExpiryDays,
		PasswordHistoryCount:        e.PasswordHistoryCount,
		PasswordBreachCheckEnabled:  e.PasswordBreachCheckEnabled,
		AccountDeletionEnabled:      e.AccountDeletionEnabled,
		EmailChangeAllowed:          e.EmailChangeAllowed,
		SessionIdleMinutes:          e.SessionIdleMinutes,
		SessionMaxHours:             e.SessionMaxHours,
		RememberMeEnabled:           e.RememberMeEnabled,
		RememberMeIdleDays:          e.RememberMeIdleDays,
		RememberMeMaxDays:           e.RememberMeMaxDays,
		LockoutThreshold:            e.LockoutThreshold,
		LockoutDurationMinutes:      e.LockoutDurationMinutes,
		IPAllowlist:                 e.IPAllowlist,
		MFARequiredGlobally:         e.MfaRequiredGlobally,
		NotificationEmailEnabled:    e.NotificationEmailEnabled,
		KeyRotationGraceHours:       e.KeyRotationGraceHours,
		KeyRotationIntervalDays:     e.KeyRotationIntervalDays,
		MFAStepUpMaxAgeMinutes:      e.MfaStepUpMaxAgeMinutes,
		PasswordResetTTLMinutes:     e.PasswordResetTTLMinutes,
		InviteTTLHours:              e.InviteTTLHours,
		SuspiciousLoginEmailEnabled: e.SuspiciousLoginEmailEnabled,
		MFATrustedDeviceEnabled:     e.MfaTrustedDeviceEnabled,
		MFATrustedDeviceDays:        e.MfaTrustedDeviceDays,
		DefaultLocale:               e.DefaultLocale,
		MailFromName:                e.MailFromName,
		MailFromAddress:             e.MailFromAddress,
		MailReplyTo:                 e.MailReplyTo,
		MailLogoURL:                 e.MailLogoURL,
		BulkLimit:                   e.BulkLimit,
		ExpiredDataRetentionDays:    e.ExpiredDataRetentionDays,
		AuditLogRetentionDays:       e.AuditLogRetentionDays,
		UpdatedAt:                   e.UpdatedAt,
		UpdatedBy:                   e.UpdatedBy,
	}
}
