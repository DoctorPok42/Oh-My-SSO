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
	settingsCacheTTL               = time.Minute
)

// DefaultInstanceSettings returns the settings a realm has before anyone
// changes them.
func DefaultInstanceSettings(realmID string) *domain.InstanceSettings {
	return &domain.InstanceSettings{
		RealmID:                 realmID,
		MinPasswordLength:       defaultMinPasswordLength,
		LockoutThreshold:        defaultLockoutThreshold,
		LockoutDurationMinutes:  defaultLockoutDurationMinutes,
		PasswordResetTTLMinutes: defaultPasswordResetTTLMinutes,
		SessionIdleMinutes:      int(defaultSessionIdleTimeout / time.Minute),
		SessionMaxHours:         int(defaultSessionMaxLifetime / time.Hour),
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

	s, err := c.repo.GetByRealmID(ctx, realmID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			c.logger.WarnContext(ctx, "cannot read instance settings, using defaults", "realm_id", realmID, "error", err)
		}
		s = DefaultInstanceSettings(realmID)
	}
	c.mu.Lock()
	c.m[realmID] = cachedSettings{s: s, fetchedAt: now}
	c.mu.Unlock()
	return s
}
