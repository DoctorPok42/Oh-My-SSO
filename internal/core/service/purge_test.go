package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// purgeRepo records each call and deletes from a pretend stock of rows
// (per realm), at most limit at a time.
type purgeRepo struct {
	stock       map[string]int       // "<realm>/<kind>" → rows left
	before      map[string]time.Time // realm → the date its ended data was purged with
	auditBefore map[string]time.Time // realm → the date its audit log was purged with
	calls       int
	failOn      string // "<realm>/sessions" fails
	cancel      func() // called by the first call, when set
	kinds       map[string][]string
	lastPurge   map[string]time.Time // realm → its last complete audit log purge
	lastFails   string               // realm whose last purge cannot be read
}

func (r *purgeRepo) LastSuccessfulAuditEntry(_ context.Context, realmID, action string) (time.Time, error) {
	if action != "audit_log.purged" {
		return time.Time{}, errors.New("unexpected action " + action)
	}
	if realmID == r.lastFails {
		return time.Time{}, errors.New("database down")
	}
	return r.lastPurge[realmID], nil
}

func (r *purgeRepo) del(kind string) func(context.Context, string, time.Time, int) (int, error) {
	return func(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
		r.calls++
		if r.cancel != nil {
			r.cancel()
			return 0, ctx.Err()
		}
		if r.kinds == nil {
			r.kinds = map[string][]string{}
		}
		r.kinds[realmID] = append(r.kinds[realmID], kind)
		if kind == "audit" {
			if r.auditBefore == nil {
				r.auditBefore = map[string]time.Time{}
			}
			r.auditBefore[realmID] = before
		} else {
			r.before[realmID] = before
		}
		if r.failOn == realmID+"/"+kind {
			return 0, errors.New("boom")
		}
		n := min(r.stock[realmID+"/"+kind], limit)
		r.stock[realmID+"/"+kind] -= n
		return n, nil
	}
}

func (r *purgeRepo) DeleteEndedSessions(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("sessions")(ctx, realmID, before, limit)
}
func (r *purgeRepo) DeleteExpiredTokens(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("tokens")(ctx, realmID, before, limit)
}
func (r *purgeRepo) DeleteEndedResetLinks(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("reset")(ctx, realmID, before, limit)
}
func (r *purgeRepo) DeleteLoginAttempts(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("attempts")(ctx, realmID, before, limit)
}
func (r *purgeRepo) DeleteUnusedKnownAccounts(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("known")(ctx, realmID, before, limit)
}
func (r *purgeRepo) DeleteExpiredTrustedDevices(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("trusted")(ctx, realmID, before, limit)
}
func (r *purgeRepo) DeleteAuditLogs(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.del("audit")(ctx, realmID, before, limit)
}

// purgeSettings: realm → settings; "broken" fails; others are not found.
type purgeSettings struct {
	repository.InstanceSettingsRepository
	byRealm map[string]*domain.InstanceSettings
}

func (s purgeSettings) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	if realmID == "broken" {
		return nil, errors.New("database down")
	}
	if st, ok := s.byRealm[realmID]; ok {
		return st, nil
	}
	return nil, repository.ErrNotFound
}

func newPurge(repo *purgeRepo, settings map[string]*domain.InstanceSettings, realms ...string) (*service.PurgeService, time.Time) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	list := make([]*domain.Realm, 0, len(realms))
	for _, id := range realms {
		list = append(list, &domain.Realm{ID: id})
	}
	return service.NewPurgeService(service.PurgeDeps{
		Purge:    repo,
		Settings: purgeSettings{byRealm: settings},
		Realms:   func(context.Context) ([]*domain.Realm, error) { return list, nil },
		Now:      func() time.Time { return now },
	}), now
}

func TestPurgeAll_UsesEachRealmsRetention(t *testing.T) {
	repo := &purgeRepo{stock: map[string]int{}, before: map[string]time.Time{}}
	svc, now := newPurge(repo, map[string]*domain.InstanceSettings{
		"custom":  {ExpiredDataRetentionDays: 30},
		"invalid": {ExpiredDataRetentionDays: 0}, // a row from before the column: the default
	}, "custom", "invalid", "unset")

	_, err := svc.PurgeAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, now.AddDate(0, 0, -30), repo.before["custom"])
	require.Equal(t, now.AddDate(0, 0, -service.DefaultRetentionDays), repo.before["invalid"])
	require.Equal(t, now.AddDate(0, 0, -service.DefaultRetentionDays), repo.before["unset"], "no settings row: the default")
	require.Equal(t, now.AddDate(0, 0, -service.DefaultRetentionDays), repo.before[""], "attempts of no realm: the default")
	require.Equal(t, []string{"tokens", "sessions", "reset", "attempts", "known", "trusted"}, repo.kinds["custom"],
		"every kind, tokens before their sessions")
	require.Equal(t, []string{"attempts"}, repo.kinds[""])
}

func TestPurgeAll_DeletesInBatchesUntilDone(t *testing.T) {
	repo := &purgeRepo{stock: map[string]int{"r/tokens": 2500, "r/known": 1000, "/attempts": 3}, before: map[string]time.Time{}}
	svc, _ := newPurge(repo, nil, "r")

	got, err := svc.PurgeAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2500, got.Tokens)
	require.Equal(t, 1000, got.KnownAccounts)
	require.Equal(t, 3, got.LoginAttempts)
	require.Equal(t, 3503, got.Total())
	require.Zero(t, repo.stock["r/tokens"])
	// tokens: 1000, 1000, 500; known: 1000, then 0 to see it is done;
	// the four other kinds once each; the attempts of no realm once.
	// plus the audit log of r (no settings: the default retention), once.
	require.Equal(t, 3+2+4+1+1, repo.calls)
}

func TestPurgeAll_OneFailureDoesNotStopTheRest(t *testing.T) {
	repo := &purgeRepo{stock: map[string]int{"a/reset": 5, "b/reset": 7}, before: map[string]time.Time{}, failOn: "a/sessions"}
	svc, _ := newPurge(repo, nil, "a", "broken", "b")

	got, err := svc.PurgeAll(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "realm a: sessions: boom")
	require.ErrorContains(t, err, "realm broken: settings: database down")
	require.Equal(t, 12, got.ResetLinks, "the other tables of a, and realm b, are purged")
	require.NotContains(t, repo.before, "broken", "a realm whose retention is unknown is left alone")
	require.Contains(t, repo.before, "", "the attempts of no realm too")
}

func TestPurgeAll_StopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repo := &purgeRepo{stock: map[string]int{}, before: map[string]time.Time{}, cancel: cancel}
	svc, _ := newPurge(repo, nil, "a", "b")

	_, err := svc.PurgeAll(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, repo.calls, "nothing more once the server stops")
}

func TestPurgeAll_AuditLogOnlyWhenTheRealmHasARetention(t *testing.T) {
	repo := &purgeRepo{stock: map[string]int{"year/audit": 2500, "forever/audit": 9}, before: map[string]time.Time{}}
	svc, now := newPurge(repo, map[string]*domain.InstanceSettings{
		"year":    {ExpiredDataRetentionDays: 30, AuditLogRetentionDays: 365},
		"forever": {AuditLogRetentionDays: 0},
		"invalid": {AuditLogRetentionDays: service.MinAuditLogRetentionDays - 1},
	}, "year", "forever", "invalid", "unset")

	got, err := svc.PurgeAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2500, got.AuditLogs, "in batches until done")
	require.Equal(t, 2500, got.Total())
	require.Equal(t, now.AddDate(0, 0, -365), repo.auditBefore["year"], "its own retention")
	require.Equal(t, now.AddDate(0, 0, -30), repo.before["year"], "the ended data keeps theirs")
	require.Equal(t, []string{"tokens", "sessions", "reset", "attempts", "known", "trusted", "audit", "audit", "audit"},
		repo.kinds["year"], "the audit log after the ended data")
	for _, kept := range []string{"forever", "invalid"} {
		require.NotContains(t, repo.kinds[kept], "audit", "%s: kept forever", kept)
	}
	require.Equal(t, now.AddDate(0, 0, -service.DefaultAuditLogRetentionDays), repo.auditBefore["unset"],
		"no settings row: the default retention")
	require.Equal(t, 9, repo.stock["forever/audit"])
}

func TestPurgeAll_AuditLogFailureIsReported(t *testing.T) {
	repo := &purgeRepo{stock: map[string]int{"a/reset": 5}, before: map[string]time.Time{}, failOn: "a/audit"}
	svc, _ := newPurge(repo, map[string]*domain.InstanceSettings{"a": {AuditLogRetentionDays: 90}}, "a")

	got, err := svc.PurgeAll(context.Background())
	require.ErrorContains(t, err, "realm a: audit log: boom")
	require.Equal(t, 5, got.ResetLinks, "the ended data is purged all the same")
}

func TestEffectiveAuditLogRetentionDays(t *testing.T) {
	require.Equal(t, service.DefaultAuditLogRetentionDays, service.EffectiveAuditLogRetentionDays(nil), "no settings: the default")
	for _, bad := range []int{-1, 1, service.MinAuditLogRetentionDays - 1, service.MaxAuditLogRetentionDays + 1} {
		require.Zero(t, service.EffectiveAuditLogRetentionDays(&domain.InstanceSettings{AuditLogRetentionDays: bad}),
			"%d: out of bounds never deletes", bad)
	}
	for _, ok := range []int{0, service.MinAuditLogRetentionDays, 365, service.MaxAuditLogRetentionDays} {
		require.Equal(t, ok, service.EffectiveAuditLogRetentionDays(&domain.InstanceSettings{AuditLogRetentionDays: ok}))
	}
}

func TestEffectiveRetentionDays(t *testing.T) {
	require.Equal(t, service.DefaultRetentionDays, service.EffectiveRetentionDays(nil))
	for _, bad := range []int{0, service.MinRetentionDays - 1, service.MaxRetentionDays + 1} {
		require.Equal(t, service.DefaultRetentionDays, service.EffectiveRetentionDays(&domain.InstanceSettings{ExpiredDataRetentionDays: bad}))
	}
	require.Equal(t, 365, service.EffectiveRetentionDays(&domain.InstanceSettings{ExpiredDataRetentionDays: 365}))
}

// B-17: what a pass deletes from a realm's audit log leaves a trace in it.
func TestPurgeAll_RecordsWhatItDeletedFromTheAuditLog(t *testing.T) {
	repo := &purgeRepo{stock: map[string]int{"busy/audit": 1500, "quiet/audit": 0}, before: map[string]time.Time{}, failOn: "broken-audit/audit"}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	settings := map[string]*domain.InstanceSettings{
		"busy": {AuditLogRetentionDays: 90}, "quiet": {AuditLogRetentionDays: 90}, "broken-audit": {AuditLogRetentionDays: 90},
	}
	var realms []*domain.Realm
	for _, id := range []string{"busy", "quiet", "broken-audit"} {
		realms = append(realms, &domain.Realm{ID: id})
	}
	auditLog := &fakeAuditRepo{}
	svc := service.NewPurgeService(service.PurgeDeps{
		Purge: repo, Settings: purgeSettings{byRealm: settings}, Audit: auditLog,
		Realms: func(context.Context) ([]*domain.Realm, error) { return realms, nil },
		Now:    func() time.Time { return now },
	})

	_, err := svc.PurgeAll(context.Background())
	require.ErrorContains(t, err, "realm broken-audit: audit log")
	require.Len(t, auditLog.entries, 1, "one entry per realm and pass that deleted something")
	e := auditLog.entries[0]
	require.Equal(t, "busy", e.RealmID)
	require.Equal(t, "audit_log.purged", e.Action)
	require.Equal(t, domain.AuditActorSystem, e.ActorType)
	require.Empty(t, e.UserID)
	require.Equal(t, domain.AuditLogSuccess, e.Status)
	require.Equal(t, 1500, e.Details["deleted"])
	require.Equal(t, 90, e.Details["retention_days"])
	require.Equal(t, now.AddDate(0, 0, -90).Format(time.RFC3339), e.Details["before"])
}

// A pass stopped half-way (server shutting down) still says what it deleted.
func TestPurgeAll_RecordsAnInterruptedAuditLogPurge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repo := &purgeRepo{stock: map[string]int{"a/audit": 2500}, before: map[string]time.Time{}}
	auditLog := &fakeAuditRepo{}
	svc := service.NewPurgeService(service.PurgeDeps{
		Purge: cancelAfterFirstAuditBatch{repo, cancel}, Settings: purgeSettings{byRealm: map[string]*domain.InstanceSettings{"a": {AuditLogRetentionDays: 30}}},
		Audit:  auditLog,
		Realms: func(context.Context) ([]*domain.Realm, error) { return []*domain.Realm{{ID: "a"}}, nil },
	})

	_, err := svc.PurgeAll(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, auditLog.entries, 1)
	e := auditLog.entries[0]
	require.Equal(t, 1000, e.Details["deleted"], "the first batch")
	require.Equal(t, true, e.Details["interrupted"])
	require.Equal(t, domain.AuditLogFailure, e.Status)
}

// cancelAfterFirstAuditBatch stops the server once one batch of the audit
// log is deleted.
type cancelAfterFirstAuditBatch struct {
	*purgeRepo
	cancel func()
}

func (r cancelAfterFirstAuditBatch) DeleteAuditLogs(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	n, err := r.purgeRepo.DeleteAuditLogs(ctx, realmID, before, limit)
	r.cancel()
	return n, err
}

// R-01 (lot B): the audit log of a realm is purged once a day, so that its
// trace is one entry a day and not one an hour.
func TestPurgeAll_PurgesTheAuditLogOnceADay(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	repo := &purgeRepo{
		stock:  map[string]int{"recent/audit": 5, "yesterday/audit": 5, "never/audit": 5, "unknown/audit": 5},
		before: map[string]time.Time{},
		lastPurge: map[string]time.Time{
			"recent":    now.Add(-23 * time.Hour),                // within the day: not again
			"yesterday": now.Add(-23*time.Hour - 31*time.Minute), // a day ago, give or take half a pass
		},
		lastFails: "unknown",
	}
	ids := []string{"recent", "yesterday", "never", "unknown"}
	settings := map[string]*domain.InstanceSettings{}
	realms := make([]*domain.Realm, 0, len(ids))
	for _, id := range ids {
		settings[id] = &domain.InstanceSettings{AuditLogRetentionDays: 90}
		realms = append(realms, &domain.Realm{ID: id})
	}
	auditLog := &fakeAuditRepo{}
	svc := service.NewPurgeService(service.PurgeDeps{
		Purge: repo, Settings: purgeSettings{byRealm: settings}, Audit: auditLog,
		Realms: func(context.Context) ([]*domain.Realm, error) { return realms, nil },
		Now:    func() time.Time { return now },
	})

	got, err := svc.PurgeAll(context.Background())
	require.ErrorContains(t, err, "realm unknown: audit log: last purge: database down")
	require.Equal(t, 10, got.AuditLogs, "yesterday and never")
	require.NotContains(t, repo.kinds["recent"], "audit", "purged less than a day ago")
	require.NotContains(t, repo.kinds["unknown"], "audit", "not without knowing the last purge")
	require.Equal(t, 5, repo.stock["recent/audit"])
	require.Equal(t, 5, repo.stock["unknown/audit"])
	traced := map[string]bool{}
	for _, e := range auditLog.entries {
		traced[e.RealmID] = true
	}
	require.Equal(t, map[string]bool{"yesterday": true, "never": true}, traced)
}
