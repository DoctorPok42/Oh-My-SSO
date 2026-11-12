package entstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5/pgconn"
)

// Postgres error codes: the revisions table, or its schema, does not exist.
const (
	pgUndefinedTable = "42P01"
	pgInvalidSchema  = "3F000"
)

// CompareMigrations compares the migrations the code expects with the ones
// Atlas recorded as applied in the database (its revisions table). missing:
// expected and not applied. unknown: applied and not expected, which happens
// when the database is ahead of the code (an older version started on it).
// A database Atlas never touched has no revisions table: everything is missing.
func CompareMigrations(ctx context.Context, db *sql.DB, expected []string) (missing, unknown []string, err error) {
	rows, err := db.QueryContext(ctx,
		`SELECT version FROM atlas_schema_revisions.atlas_schema_revisions WHERE applied = total`)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == pgUndefinedTable || pgErr.Code == pgInvalidSchema) {
			return slices.Clone(expected), nil, nil
		}
		return nil, nil, err
	}
	defer rows.Close()

	var applied []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, nil, err
		}
		applied = append(applied, version)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	for _, v := range expected {
		if !slices.Contains(applied, v) {
			missing = append(missing, v)
		}
	}
	for _, v := range applied {
		if !slices.Contains(expected, v) {
			unknown = append(unknown, v)
		}
	}
	slices.Sort(unknown)
	return missing, unknown, nil
}
