package app

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"sso.internal/sso/ent/migrate/migrations"
	"sso.internal/sso/internal/storage/entstore"
)

// CheckSchema stops a server that would run on a database older than its
// code: it would start, then fail request after request on a missing column.
// The migrations are applied before the servers start (the migrate service,
// make migrate-apply). A database ahead of the code (an older version
// started again after a deploy) is allowed, with a warning: a rollback is
// possible when the migrations since were additive.
func CheckSchema(ctx context.Context, db *sql.DB) error {
	missing, unknown, err := entstore.CompareMigrations(ctx, db, migrations.Versions())
	if err != nil {
		return fmt.Errorf("read the applied migrations: %w", err)
	}
	if len(missing) > 0 {
		return fmt.Errorf("the database lacks %d migration(s) this version needs (%s): apply them first "+
			"(the migrate service of compose.yml, or make migrate-apply)", len(missing), listVersions(missing))
	}
	if len(unknown) > 0 {
		log.Printf("database: %d migration(s) applied are unknown to this version (%s): the database is ahead of the code",
			len(unknown), listVersions(unknown))
	}
	return nil
}

// listVersions names the first versions of a long list: a database Atlas
// never touched lacks all of them.
func listVersions(versions []string) string {
	const shown = 3
	if len(versions) <= shown {
		return strings.Join(versions, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(versions[:shown], ", "), len(versions)-shown)
}

func checkSchemaOrExit(db *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := CheckSchema(ctx, db); err != nil {
		log.Fatalf("db: %v", err)
	}
}
