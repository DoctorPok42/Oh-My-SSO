package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core/audit"
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
// entries for good within a day (the audit log is purged once a day,
// auditLogPurgeGap).
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
	// Audit receives the audit_log.purged entries: one per realm and day
	// that deleted audit log entries. Optional; without it the audit log is
	// purged at every pass.
	Audit  repository.AuditLogRepository
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
	Emails         int // e-mails of the outbox
	AuditLogs      int
}

func (c PurgeCounts) Total() int {
	return c.ended() + c.AuditLogs
}

// ended: the rows of data that had ended (all but the audit log).
func (c PurgeCounts) ended() int {
	return c.Sessions + c.Tokens + c.ResetLinks + c.LoginAttempts + c.KnownAccounts + c.TrustedDevices + c.Emails
}

func (c *PurgeCounts) add(o PurgeCounts) {
	c.Sessions += o.Sessions
	c.Tokens += o.Tokens
	c.ResetLinks += o.ResetLinks
	c.LoginAttempts += o.LoginAttempts
	c.KnownAccounts += o.KnownAccounts
	c.TrustedDevices += o.TrustedDevices
	c.Emails += o.Emails
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
			c.AuditLogs, err = s.purgeAuditLogDaily(ctx, r.ID, now, auditDays)
			if err != nil {
				errs = append(errs, fmt.Errorf("realm %s: audit log: %w", r.ID, err))
			}
		}
		total.add(c)
		if c.ended() > 0 {
			s.d.Logger.InfoContext(ctx, "purge: expired data deleted", "realm_id", r.ID, "retention_days", days,
				"sessions", c.Sessions, "tokens", c.Tokens, "reset_links", c.ResetLinks,
				"login_attempts", c.LoginAttempts, "known_accounts", c.KnownAccounts, "trusted_devices", c.TrustedDevices, "emails", c.Emails)
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

// auditLogPurgeGap: a realm's audit log is purged once a day, not at every
// pass, so that its trace (audit_log.purged) is one entry a day and not one
// an hour. The gap is half a pass short of a day, so that the hourly passes
// do not drift an hour later every day. The retention is kept within a day.
const auditLogPurgeGap = 24*time.Hour - PurgeInterval/2

// purgeAuditLogDaily deletes the entries of the realm's audit log older
// than its retention, unless its last complete purge is less than
// auditLogPurgeGap old, and leaves the trace of what it deleted. The last
// purge is read from the audit log itself (its last audit_log.purged entry
// with the status success): every server sees it, and a pass that stopped
// half-way does not count, the next one finishes the day. Two servers
// starting the same day's purge at the same moment write one trace each,
// for different entries (SKIP LOCKED): the counts add up.
func (s *PurgeService) purgeAuditLogDaily(ctx context.Context, realmID string, now time.Time, days int) (int, error) {
	last, err := s.d.Purge.LastSuccessfulAuditEntry(ctx, realmID, audit.AuditLogPurged)
	if err != nil {
		// Not without it: the realm would get a trace every hour.
		return 0, fmt.Errorf("last purge: %w", err)
	}
	if !last.IsZero() && now.Sub(last) < auditLogPurgeGap {
		return 0, nil
	}
	before := now.AddDate(0, 0, -days)
	n, err := s.PurgeAuditLogs(ctx, realmID, before)
	s.auditPurged(ctx, realmID, n, before, days, err)
	return n, err
}

// auditPurged leaves in the realm's audit log the trace of what a purge
// deleted from it: how many entries, written before when. Nothing when it
// deleted none: the next pass tries again, an hour later. A purge that did
// not finish (server stopping, database error) still says what it deleted,
// with the status failure and "interrupted".
func (s *PurgeService) auditPurged(ctx context.Context, realmID string, deleted int, before time.Time, retentionDays int, purgeErr error) {
	if s.d.Audit == nil || deleted == 0 {
		return
	}
	details := map[string]interface{}{
		"deleted":        deleted,
		"before":         before.UTC().Format(time.RFC3339),
		"retention_days": retentionDays,
	}
	status := domain.AuditLogSuccess
	if purgeErr != nil {
		status, details["interrupted"] = domain.AuditLogFailure, true
	}
	// Even when the pass was stopped (server shutting down): the rows are
	// gone, their trace must not be.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      realmID,
		ActorType:    domain.AuditActorSystem, // the retention policy, not a person
		Action:       audit.AuditLogPurged,
		ResourceType: "AuditLog",
		Level:        domain.AuditLogInfo,
		Status:       status,
		Details:      details,
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "purge: audit_log.purged not written", "realm_id", realmID, "deleted", deleted, "error", err)
	}
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
		{"verification links", &c.ResetLinks, s.d.Purge.DeleteEndedVerificationLinks},
		{"e-mails", &c.Emails, s.d.Purge.DeleteEndedEmails},
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
