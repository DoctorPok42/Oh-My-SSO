package entstore_test

// The versioned migrations (ent/migrate/migrations) are what production runs
// (`atlas migrate apply` in compose.example.yml), but every other test builds
// its tables with client.Schema.Create, straight from the Ent schema. Without
// this test, a migration file that is missing, edited by hand or broken would
// pass the whole suite and only fail in production.
//
// It does what `make migrate-diff` does, with Ent's own API: check atlas.sum,
// replay every migration file on an empty database, compare the result with
// the Ent schema (ent/migrate/schema.go). Any difference means a migration is
// missing: run `make migrate-diff name=<what_changed>` and commit the file.
// https://entgo.io/docs/versioned-migrations

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	atlasmigrate "ariga.io/atlas/sql/migrate"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	entmigrate "sso.internal/sso/ent/migrate"
)

// migrationsDir is relative to this package (go test runs in its directory).
const migrationsDir = "../../../ent/migrate/migrations"

func TestMigrations_MatchEntSchema_Integration(t *testing.T) {
	ctx := context.Background()

	// An in-memory copy: if the schemas differ, Ent writes the missing
	// migration into it, never into the repository.
	dir := copyToMemDir(t, migrationsDir)
	before := sqlFileNames(t, dir)
	require.NotEmpty(t, before, "no migration file found in %s", migrationsDir)

	db, err := sql.Open("pgx", newEmptyDatabase(t, ctx))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	m, err := schema.NewMigrate(entsql.OpenDB(dialect.Postgres, db),
		schema.WithDir(dir),
		schema.WithFormatter(atlasmigrate.DefaultFormatter),
		// Replay the files on the empty database to get the current state
		// (like --dev-url), instead of inspecting a live database.
		schema.WithMigrationMode(schema.ModeReplay),
		// Ent hides dropped columns and indexes by default: report them too.
		schema.WithDropColumn(true),
		schema.WithDropIndex(true),
	)
	require.NoError(t, err)

	// NamedDiff checks atlas.sum, replays the files (an SQL error fails
	// here), then writes a new migration only if something is missing.
	require.NoError(t, m.NamedDiff(ctx, "missing", entmigrate.Tables...),
		"atlas.sum mismatch: a migration file was edited or added by hand? Run `atlas migrate hash` after checking it")

	files, err := dir.Files()
	require.NoError(t, err)
	for _, f := range files {
		if before[f.Name()] {
			continue
		}
		t.Errorf("the Ent schema has changes that no migration creates.\n"+
			"Run: make migrate-diff name=<what_changed>, then commit the new file.\n"+
			"The missing migration would be:\n%s", f.Bytes())
	}
}

// copyToMemDir copies a migration directory (the .sql files and atlas.sum).
func copyToMemDir(t *testing.T, path string) *atlasmigrate.MemDir {
	t.Helper()
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	dir := atlasmigrate.OpenMemDir("migrations-check-" + uuid.NewString())
	t.Cleanup(func() { _ = dir.Close() })
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(path, e.Name()))
		require.NoError(t, err)
		require.NoError(t, dir.WriteFile(e.Name(), b))
	}
	return dir
}

func sqlFileNames(t *testing.T, dir atlasmigrate.Dir) map[string]bool {
	t.Helper()
	files, err := dir.Files()
	require.NoError(t, err)
	out := make(map[string]bool, len(files))
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			out[f.Name()] = true
		}
	}
	return out
}

// newEmptyDatabase creates a database without any table in the shared
// container, dropped at the end of the test, and returns its DSN.
func newEmptyDatabase(t *testing.T, ctx context.Context) string {
	t.Helper()
	admin, err := sql.Open("pgx", testDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })

	name := "migrations_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})

	u, err := url.Parse(testDSN)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}
