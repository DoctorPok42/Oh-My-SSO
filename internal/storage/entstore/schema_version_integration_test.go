package entstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/storage/entstore"
)

func TestCompareMigrations(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("pgx", testDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	exec := func(query string) {
		t.Helper()
		_, err := db.ExecContext(ctx, query)
		require.NoError(t, err)
	}
	expected := []string{"20260101000000", "20260201000000", "20260301000000"}

	exec(`DROP SCHEMA IF EXISTS atlas_schema_revisions CASCADE`)
	t.Cleanup(func() { _, _ = db.Exec(`DROP SCHEMA IF EXISTS atlas_schema_revisions CASCADE`) })

	t.Run("Atlas never ran: everything is missing", func(t *testing.T) {
		missing, unknown, err := entstore.CompareMigrations(ctx, db, expected)
		require.NoError(t, err)
		require.Equal(t, expected, missing)
		require.Empty(t, unknown)
	})

	// The columns of Atlas's revisions table that are read.
	exec(`CREATE SCHEMA atlas_schema_revisions`)
	exec(`CREATE TABLE atlas_schema_revisions.atlas_schema_revisions (version varchar PRIMARY KEY, applied bigint NOT NULL, total bigint NOT NULL)`)
	exec(`INSERT INTO atlas_schema_revisions.atlas_schema_revisions VALUES
		('20260101000000', 2, 2),
		('20260201000000', 1, 3),
		('20250101000000', 1, 1)`)

	t.Run("a migration stopped half way is not applied", func(t *testing.T) {
		missing, unknown, err := entstore.CompareMigrations(ctx, db, expected)
		require.NoError(t, err)
		require.Equal(t, []string{"20260201000000", "20260301000000"}, missing)
		require.Equal(t, []string{"20250101000000"}, unknown)
	})

	t.Run("up to date", func(t *testing.T) {
		exec(`DELETE FROM atlas_schema_revisions.atlas_schema_revisions WHERE version = '20250101000000'`)
		exec(`UPDATE atlas_schema_revisions.atlas_schema_revisions SET applied = total`)
		exec(`INSERT INTO atlas_schema_revisions.atlas_schema_revisions VALUES ('20260301000000', 1, 1)`)
		missing, unknown, err := entstore.CompareMigrations(ctx, db, expected)
		require.NoError(t, err)
		require.Empty(t, missing)
		require.Empty(t, unknown)
	})

	t.Run("a database ahead of the code", func(t *testing.T) {
		exec(`INSERT INTO atlas_schema_revisions.atlas_schema_revisions VALUES ('20260401000000', 1, 1)`)
		missing, unknown, err := entstore.CompareMigrations(ctx, db, expected)
		require.NoError(t, err)
		require.Empty(t, missing)
		require.Equal(t, []string{"20260401000000"}, unknown)
	})
}
