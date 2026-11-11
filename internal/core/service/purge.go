package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Data that has ended is kept for the realm's expired_data_retention_days
// (Settings), DefaultRetentionDays until it is changed, then deleted:
// sessions and tokens after they expired or were revoked, used or expired
// reset / activation links, sign-in attempts, accounts of "Pick an account"
// and trusted devices unused for that long. Without it these tables grow
// forever. The default is the history the suspicious sign-in check looks at
// (loginHistoryWindow): a shorter one makes it see more devices as new.
const (
	DefaultRetentionDays = 90
	MinRetentionDays     = 7
	MaxRetentionDays     = 3650

	// PurgeInterval: how often the purge runs.
	PurgeInterval = time.Hour
	// purgeBatch: the most rows one DELETE removes.
	purgeBatch = 1000
)

// The audit log has its own retention, audit_log_retention_days (Settings >
// Audit): DefaultAuditLogRetentionDays until the realm changes it, 0 = kept
// forever. It is evidence of who did what, not data that has ended: the
// retention of expired data never touches it, and a shorter one deletes
// entries for good at the next pass.
const (
	DefaultAuditLogRetentionDays = 365
	MinAuditLogRetentionDays     = 30
	MaxAuditLogRetentionDays     = 3650
)

// EffectiveRetentionDays is the realm's expired_data_retention_days,
// DefaultRetentionDays when it has no valid one.
func EffectiveRetentionDays(st *domain.InstanceSettings) int {
	if st == nil || st.ExpiredDataRetentionDays < MinRetentionDays || st.ExpiredDataRetentionDays > MaxRetentionDays {
		return DefaultRetentionDays
	}
	return st.ExpiredDataRetentionDays
}

// EffectiveAuditLogRetentionDays is the realm's audit_log_retention_days,
// DefaultAuditLogRetentionDays when it has no settings. A stored value out of
// bounds means 0 (kept forever): it never deletes the audit log.
func EffectiveAuditLogRetentionDays(st *domain.InstanceSettings) int {
	if st == nil {
		return DefaultAuditLogRetentionDays
	}
	if !validAuditLogRetention(st.AuditLogRetentionDays) {
		return 0
	}
	return st.AuditLogRetentionDays
}

// validAuditLogRetention: 0 (forever), or MinAuditLogRetentionDays to
// MaxAuditLogRetentionDays.
func validAuditLogRetention(days int) bool {
	return days == 0 || (days >= MinAuditLogRetentionDays && days <= MaxAuditLogRetentionDays)
}

type PurgeDeps struct {
	Purge    repository.PurgeRepository
	Settings repository.InstanceSettingsRepository
	// Realms lists every realm (AdminRepository.ListRealms).
	Realms func(context.Context) ([]*domain.Realm, error)
	Logger *slog.Logger
	Now    func() time.Time
}

// PurgeService deletes the data that ended longer ago than the retention
// of its realm, and the audit log entries older than its audit retention.
type PurgeService struct {
	d PurgeDeps
}

func NewPurgeService(d PurgeDeps) *PurgeService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &PurgeService{d: d}
}

// PurgeCounts: how many rows a purge deleted, per kind.
type PurgeCounts struct {
	Sessions       int
	Tokens         int
	ResetLinks     int
	LoginAttempts  int
	KnownAccounts  int
	TrustedDevices int
	AuditLogs      int
}

func (c PurgeCounts) Total() int {
	return c.ended() + c.AuditLogs
}

// ended: the rows of data that had ended (all but the audit log).
func (c PurgeCounts) ended() int {
	return c.Sessions + c.Tokens + c.ResetLinks + c.LoginAttempts + c.KnownAccounts + c.TrustedDevices
}

func (c *PurgeCounts) add(o PurgeCounts) {
	c.Sessions += o.Sessions
	c.Tokens += o.Tokens
	c.ResetLinks += o.ResetLinks
	c.LoginAttempts += o.LoginAttempts
	c.KnownAccounts += o.KnownAccounts
	c.TrustedDevices += o.TrustedDevices
	c.AuditLogs += o.AuditLogs
}

// Run purges every realm every `every`, until ctx is done. Several servers
// may run it at once: each row is deleted by one of them (SKIP LOCKED).
func (s *PurgeService) Run(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if _, err := s.PurgeAll(ctx); err != nil && ctx.Err() == nil {
			s.d.Logger.WarnContext(ctx, "purge", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// PurgeAll purges every realm with its own retentions (expired data, and
// the audit log when the realm keeps it for a limited time), then the
// sign-in attempts of no existing realm with the default one.
func (s *PurgeService) PurgeAll(ctx context.Context) (PurgeCounts, error) {
	var total PurgeCounts
	realms, err := s.d.Realms(ctx)
	if err != nil {
		return total, fmt.Errorf("purge: list realms: %w", err)
	}
	now := s.d.Now()
	var errs []error
	for _, r := range realms {
		st, err := s.settings(ctx, r.ID)
		if err != nil {
			// Not with the defaults: they may be shorter than what the
			// realm asks for.
			errs = append(errs, fmt.Errorf("realm %s: settings: %w", r.ID, err))
			continue
		}
		days, auditDays := EffectiveRetentionDays(st), EffectiveAuditLogRetentionDays(st)
		c, err := s.PurgeRealm(ctx, r.ID, now.AddDate(0, 0, -days))
		if err != nil {
			errs = append(errs, fmt.Errorf("realm %s: %w", r.ID, err))
		}
		if auditDays > 0 && ctx.Err() == nil {
			c.AuditLogs, err = s.PurgeAuditLogs(ctx, r.ID, now.AddDate(0, 0, -auditDays))
			if err != nil {
				errs = append(errs, fmt.Errorf("realm %s: audit log: %w", r.ID, err))
			}
		}
		total.add(c)
		if c.ended() > 0 {
			s.d.Logger.InfoContext(ctx, "purge: expired data deleted", "realm_id", r.ID, "retention_days", days,
				"sessions", c.Sessions, "tokens", c.Tokens, "reset_links", c.ResetLinks,
				"login_attempts", c.LoginAttempts, "known_accounts", c.KnownAccounts, "trusted_devices", c.TrustedDevices)
		}
		if c.AuditLogs > 0 {
			s.d.Logger.InfoContext(ctx, "purge: audit log entries deleted", "realm_id", r.ID,
				"audit_log_retention_days", auditDays, "audit_logs", c.AuditLogs)
		}
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
	n, err := drain(ctx, func(limit int) (int, error) {
		return s.d.Purge.DeleteLoginAttempts(ctx, "", now.AddDate(0, 0, -DefaultRetentionDays), limit)
	})
	total.LoginAttempts += n
	if err != nil {
		errs = append(errs, fmt.Errorf("sign-in attempts of no realm: %w", err))
	}
	return total, errors.Join(errs...)
}

// settings: nil when the realm has no settings row (the defaults apply).
func (s *PurgeService) settings(ctx context.Context, realmID string) (*domain.InstanceSettings, error) {
	st, err := s.d.Settings.GetByRealmID(ctx, realmID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	return st, err
}

// PurgeAuditLogs deletes the entries of a realm's audit log written before
// `before`, in batches like the rest.
func (s *PurgeService) PurgeAuditLogs(ctx context.Context, realmID string, before time.Time) (int, error) {
	return drain(ctx, func(limit int) (int, error) { return s.d.Purge.DeleteAuditLogs(ctx, realmID, before, limit) })
}

// PurgeRealm deletes the data of a realm that ended before `before`. It
// goes on after an error, so that one table does not hold back the others.
func (s *PurgeService) PurgeRealm(ctx context.Context, realmID string, before time.Time) (PurgeCounts, error) {
	var c PurgeCounts
	var errs []error
	for _, step := range []struct {
		name  string
		count *int
		del   func(context.Context, string, time.Time, int) (int, error)
	}{
		// Tokens first: deleting a session takes its tokens along, but a
		// token may expire long before its session does.
		{"tokens", &c.Tokens, s.d.Purge.DeleteExpiredTokens},
		{"sessions", &c.Sessions, s.d.Purge.DeleteEndedSessions},
		{"reset links", &c.ResetLinks, s.d.Purge.DeleteEndedResetLinks},
		{"sign-in attempts", &c.LoginAttempts, s.d.Purge.DeleteLoginAttempts},
		{"known accounts", &c.KnownAccounts, s.d.Purge.DeleteUnusedKnownAccounts},
		{"trusted devices", &c.TrustedDevices, s.d.Purge.DeleteExpiredTrustedDevices},
	} {
		n, err := drain(ctx, func(limit int) (int, error) { return step.del(ctx, realmID, before, limit) })
		*step.count += n
		if err != nil {
			if ctx.Err() != nil {
				return c, ctx.Err()
			}
			errs = append(errs, fmt.Errorf("%s: %w", step.name, err))
		}
	}
	return c, errors.Join(errs...)
}

// drain calls del with purgeBatch until a call deletes fewer rows (the
// rest, if any, is locked by another server, which deletes it).
func drain(ctx context.Context, del func(limit int) (int, error)) (int, error) {
	total := 0
	for {
		n, err := del(purgeBatch)
		total += n
		if err != nil || n < purgeBatch {
			return total, err
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}
