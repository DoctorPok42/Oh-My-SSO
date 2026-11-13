package repository

import (
	"context"
	"time"
)

// PurgeRepository deletes the data of a realm that ended before a date
// (service.PurgeService). Each method deletes at most limit rows and returns
// how many it deleted: the caller repeats until fewer than limit are gone, so
// no statement holds its locks for long. Rows another server is deleting at
// the same moment are skipped, never waited for (FOR UPDATE SKIP LOCKED):
// every server may purge at once.
type PurgeRepository interface {
	// DeleteEndedSessions removes the sessions that expired before
	// `before`, and those that ended (revoked, expired) and were last used
	// before it. Their tokens go with them.
	DeleteEndedSessions(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// DeleteExpiredTokens removes the tokens that expired before `before`,
	// except the used refresh tokens of a session still active: presenting
	// one again is a replay, which revokes its family.
	DeleteExpiredTokens(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// DeleteEndedResetLinks removes the reset and activation links of the
	// realm's users that expired, or were used, before `before`.
	DeleteEndedResetLinks(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// DeleteLoginAttempts removes the sign-in attempts made before
	// `before`. realmID "": the attempts of no existing realm.
	DeleteLoginAttempts(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// DeleteUnusedKnownAccounts removes the accounts of "Pick an account"
	// last used before `before`.
	DeleteUnusedKnownAccounts(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// DeleteExpiredTrustedDevices removes the trusted devices whose trust
	// ended before `before`.
	DeleteExpiredTrustedDevices(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// DeleteAuditLogs removes the entries of the realm's audit log written
	// before `before` (its own retention, audit_log_retention_days).
	DeleteAuditLogs(ctx context.Context, realmID string, before time.Time, limit int) (int, error)
	// LastSuccessfulAuditEntry is when the realm's audit log last recorded
	// action with the status success; zero when it never did. The audit log
	// is purged once a day: its last audit_log.purged entry tells when.
	LastSuccessfulAuditEntry(ctx context.Context, realmID, action string) (time.Time, error)
}
