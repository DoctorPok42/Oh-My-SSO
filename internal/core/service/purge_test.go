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
