// Package migrations tells which migrations this version of the code expects
// the database to have. The SQL files themselves are applied by Atlas.
package migrations

import (
	"embed"
	"strings"
)

//go:embed *.sql
var files embed.FS

// Versions are the versions of the migrations of this directory, oldest first
// ("20261111190000" for 20261111190000_normalize_user_identifiers.sql): the
// "version" column of Atlas's revisions table.
func Versions() []string {
	entries, err := files.ReadDir(".")
	if err != nil {
		panic("migrations: " + err.Error()) // embedded files: a bug, not a runtime error
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		version, _, _ := strings.Cut(e.Name(), "_")
		versions = append(versions, version)
	}
	return versions
}
