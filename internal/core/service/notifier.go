package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type Notifier interface {
	Notify(ctx context.Context, e domain.NotificationEvent)
}

// NopNotifier drops every event (no e-mail configured, or tests).
type NopNotifier struct{}

func (NopNotifier) Notify(context.Context, domain.NotificationEvent) {}


const (
	defaultMinPasswordLength       = 12
	defaultLockoutThreshold        = 5
	defaultLockoutDurationMinutes  = 15
	defaultPasswordResetTTLMinutes = 30
	defaultInviteTTLHours          = 4
	settingsCacheTTL               = time.Minute
)

// DefaultInstanceSettings returns the settings a realm has before anyone
// changes them.
func DefaultInstanceSettings(realmID string) *domain.InstanceSettings {
	return &domain.InstanceSettings{
		RealmID:                  realmID,
		MinPasswordLength:        defaultMinPasswordLength,
		LockoutThreshold:         defaultLockoutThreshold,
		LockoutDurationMinutes:   defaultLockoutDurationMinutes,
		PasswordResetTTLMinutes:  defaultPasswordResetTTLMinutes,
		InviteTTLHours:           defaultInviteTTLHours,
		SessionIdleMinutes:       int(defaultSessionIdleTimeout / time.Minute),
		SessionMaxHours:          int(defaultSessionMaxLifetime / time.Hour),
		RememberMeEnabled:        true,
		RememberMeIdleDays:       defaultRememberMeIdleDays,
		RememberMeMaxDays:        defaultRememberMeMaxDays,
		BulkLimit:                DefaultBulkLimit,
		ExpiredDataRetentionDays: DefaultRetentionDays,
		AuditLogRetentionDays:    DefaultAuditLogRetentionDays,
	}
}

// settingsCache reads InstanceSettings with a one-minute cache: the login
// path needs the lockout policy on every request, and a policy change taking
// up to a minute to apply is fine (same rule as the session policy).
type settingsCache struct {
	repo   repository.InstanceSettingsRepository
	now    func() time.Time
	logger *slog.Logger

	mu sync.Mutex
	m  map[string]cachedSettings
}

type cachedSettings struct {
	s         *domain.InstanceSettings
	fetchedAt time.Time
	// fallback: the defaults, put there because the database did not answer.
	// getStrict does not trust them.
	fallback bool
}

func newSettingsCache(repo repository.InstanceSettingsRepository, logger *slog.Logger) *settingsCache {
	if logger == nil {
		logger = slog.Default()
	}
	return &settingsCache{repo: repo, now: time.Now, logger: logger, m: map[string]cachedSettings{}}
}

// get never fails: on a missing row or a database error it returns the
// defaults (and logs the error), like SessionService.loadPolicy.
func (c *settingsCache) get(ctx context.Context, realmID string) *domain.InstanceSettings {
	if c == nil || c.repo == nil {
		return DefaultInstanceSettings(realmID)
	}
	now := c.now()
	c.mu.Lock()
	e, ok := c.m[realmID]
	c.mu.Unlock()
	if ok && now.Sub(e.fetchedAt) < settingsCacheTTL {
		return e.s
	}

	s, err := c.fetch(ctx, realmID, now)
	if err != nil {
		c.logger.WarnContext(ctx, "cannot read instance settings, using defaults", "realm_id", realmID, "error", err)
		s = DefaultInstanceSettings(realmID)
		c.mu.Lock()
		c.m[realmID] = cachedSettings{s: s, fetchedAt: now, fallback: true}
		c.mu.Unlock()
	}
	return s
}

// getStrict is get for a decision that must not fall back to the defaults
// (the IP allowlist: the defaults have none, so they would let everyone in).
// A database error is returned, and not cached; a realm without a settings
// row has the defaults.
func (c *settingsCache) getStrict(ctx context.Context, realmID string) (*domain.InstanceSettings, error) {
	if c == nil || c.repo == nil {
		return DefaultInstanceSettings(realmID), nil
	}
	now := c.now()
	c.mu.Lock()
	e, ok := c.m[realmID]
	c.mu.Unlock()
	if ok && !e.fallback && now.Sub(e.fetchedAt) < settingsCacheTTL {
		return e.s, nil
	}
	return c.fetch(ctx, realmID, now)
}

// fetch reads the settings of a realm and caches them. A missing row is the
// defaults (cached too); any other error is returned.
func (c *settingsCache) fetch(ctx context.Context, realmID string, now time.Time) (*domain.InstanceSettings, error) {
	s, err := c.repo.GetByRealmID(ctx, realmID)
	if errors.Is(err, repository.ErrNotFound) {
		s, err = DefaultInstanceSettings(realmID), nil
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.m[realmID] = cachedSettings{s: s, fetchedAt: now}
	c.mu.Unlock()
	return s, nil
}
