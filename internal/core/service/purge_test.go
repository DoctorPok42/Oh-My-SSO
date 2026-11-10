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
	stock  map[string]int       // realm → rows left, for every kind
	before map[string]time.Time // realm → the date it was purged with
	calls  int
	failOn string // "<realm>/sessions" fails
	cancel func() // called by the first call, when set
	kinds  map[string][]string
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
		r.before[realmID] = before
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
	require.Equal(t, 3+2+4+1, repo.calls)
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

func TestEffectiveRetentionDays(t *testing.T) {
	require.Equal(t, service.DefaultRetentionDays, service.EffectiveRetentionDays(nil))
	for _, bad := range []int{0, service.MinRetentionDays - 1, service.MaxRetentionDays + 1} {
		require.Equal(t, service.DefaultRetentionDays, service.EffectiveRetentionDays(&domain.InstanceSettings{ExpiredDataRetentionDays: bad}))
	}
	require.Equal(t, 365, service.EffectiveRetentionDays(&domain.InstanceSettings{ExpiredDataRetentionDays: 365}))
}
