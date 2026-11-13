package entstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent/auditlog"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

func TestPurgeRepository_LastSuccessfulAuditEntry_Integration(t *testing.T) {
	f := newRBACFixture(t)
	other := newTestRealm(t, f.ctx, f.client)
	purge := entstore.NewPurgeRepository(f.client)
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(realmID, action string, status entschema.AuditLogStatus, at time.Time) {
		_, err := f.client.AuditLog.Create().SetRealmID(realmID).SetAction(action).SetStatus(status).SetTimestamp(at).Save(f.ctx)
		require.NoError(t, err)
	}

	last, err := purge.LastSuccessfulAuditEntry(f.ctx, f.realm.ID, audit.AuditLogPurged)
	require.NoError(t, err)
	require.True(t, last.IsZero(), "never purged")

	success := entschema.AuditLogStatus(domain.AuditLogSuccess)
	mk(f.realm.ID, audit.AuditLogPurged, success, now.Add(-48*time.Hour))
	mk(f.realm.ID, audit.AuditLogPurged, success, now.Add(-30*time.Hour)) // the one
	mk(f.realm.ID, audit.AuditLogPurged, entschema.AuditLogStatus(domain.AuditLogFailure), now.Add(-time.Hour))
	mk(f.realm.ID, audit.AuthLogin, success, now)
	mk(other.ID, audit.AuditLogPurged, success, now)

	last, err = purge.LastSuccessfulAuditEntry(f.ctx, f.realm.ID, audit.AuditLogPurged)
	require.NoError(t, err)
	require.True(t, now.Add(-30*time.Hour).Equal(last),
		"the latest success of that action in that realm: not a failure, another action or another realm (%s)", last)
}

// R-01 (lot B): one purge of the audit log, and one trace, a day per realm.
func TestPurgeService_AuditLogOnceADay_Integration(t *testing.T) {
	f := newRBACFixture(t)
	now := time.Now()
	clock := now
	svc := service.NewPurgeService(service.PurgeDeps{
		Purge:    entstore.NewPurgeRepository(f.client),
		Settings: entstore.NewInstanceSettingsRepository(f.client), // no row: 365 days
		Audit:    entstore.NewAuditLogRepository(f.client),
		Realms:   func(context.Context) ([]*domain.Realm, error) { return []*domain.Realm{f.realm}, nil },
		Now:      func() time.Time { return clock },
	})
	old := func() {
		_, err := f.client.AuditLog.Create().SetRealmID(f.realm.ID).SetAction(audit.AuthLogin).
			SetTimestamp(now.AddDate(0, 0, -400)).Save(f.ctx)
		require.NoError(t, err)
	}
	traces := func() int {
		n, err := f.client.AuditLog.Query().Where(auditlog.RealmID(f.realm.ID), auditlog.Action(audit.AuditLogPurged)).Count(f.ctx)
		require.NoError(t, err)
		return n
	}

	old()
	old()
	got, err := svc.PurgeAll(f.ctx)
	require.NoError(t, err)
	require.Equal(t, 2, got.AuditLogs)
	require.Equal(t, 1, traces())

	old() // crosses the retention an hour later
	clock = now.Add(time.Hour)
	got, err = svc.PurgeAll(f.ctx)
	require.NoError(t, err)
	require.Zero(t, got.AuditLogs, "purged less than a day ago")
	require.Equal(t, 1, traces(), "no trace an hour later")

	clock = now.Add(24 * time.Hour)
	got, err = svc.PurgeAll(f.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, got.AuditLogs, "the next day")
	require.Equal(t, 2, traces())
}
