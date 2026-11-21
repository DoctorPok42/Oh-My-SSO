package entstore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

func TestDataExportRepository_Integration(t *testing.T) {
	f := newRBACFixture(t)
	repo := entstore.NewDataExportRepository(f.client)
	purge := entstore.NewPurgeRepository(f.client)
	u := f.user()
	now := time.Now().UTC().Truncate(time.Microsecond)
	start := func(at time.Time) (*domain.DataExport, error) {
		e := &domain.DataExport{RealmID: f.realm.ID, UserID: u.ID, CreatedAt: at, ExpiresAt: at.Add(7 * 24 * time.Hour)}
		return e, repo.Start(f.ctx, e, now.Add(-15*time.Minute))
	}

	_, err := repo.GetByUser(f.ctx, u.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)

	first, err := start(now)
	require.NoError(t, err)
	require.NotEmpty(t, first.ID)
	_, err = start(now)
	require.ErrorIs(t, err, repository.ErrConflict, "one copy at a time")

	require.NoError(t, repo.Finish(f.ctx, first.ID, domain.DataExportReady, []byte(`{"a":1}`), now, now.Add(time.Hour)))
	got, err := repo.GetByUser(f.ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DataExportReady, got.Status)
	require.Nil(t, got.Data, "the status, without the copy")
	data, err := repo.GetData(f.ctx, first.ID)
	require.NoError(t, err)
	require.JSONEq(t, `{"a":1}`, string(data))
	require.NotNil(t, got.FinishedAt)
	require.WithinDuration(t, now.Add(time.Hour), got.ExpiresAt, time.Millisecond)

	// A finished copy is replaced by a new request; the old one cannot
	// be finished again.
	second, err := start(now)
	require.NoError(t, err)
	require.NotEqual(t, first.ID, second.ID)
	require.NoError(t, repo.Finish(f.ctx, first.ID, domain.DataExportFailed, nil, now, now))
	got, err = repo.GetByUser(f.ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, second.ID, got.ID)
	require.Equal(t, domain.DataExportRunning, got.Status)

	// A running copy older than staleBefore is replaced too.
	stale := f.user()
	old := &domain.DataExport{RealmID: f.realm.ID, UserID: stale.ID, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, repo.Start(f.ctx, old, now.Add(-2*time.Hour)))
	fresh := &domain.DataExport{RealmID: f.realm.ID, UserID: stale.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, repo.Start(f.ctx, fresh, now.Add(-15*time.Minute)))

	// The purge deletes the copies past their date, whatever their realm.
	n, err := purge.DeleteExpiredDataExports(f.ctx, now.Add(2*time.Hour), 100)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 1)
	_, err = repo.GetByUser(f.ctx, stale.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)

	// Deleting the account deletes its copy.
	third := f.user()
	e := &domain.DataExport{RealmID: f.realm.ID, UserID: third.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, repo.Start(f.ctx, e, now))
	require.NoError(t, f.client.User.DeleteOneID(third.ID).Exec(f.ctx))
	_, err = repo.GetByUser(f.ctx, third.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
}
