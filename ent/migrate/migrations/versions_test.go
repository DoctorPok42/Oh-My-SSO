package migrations_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent/migrate/migrations"
)

func TestVersions(t *testing.T) {
	files, err := filepath.Glob("*.sql")
	require.NoError(t, err)
	versions := migrations.Versions()

	require.NotEmpty(t, versions)
	require.Len(t, versions, len(files))
	require.True(t, slices.IsSorted(versions))
	require.Len(t, slices.Compact(slices.Clone(versions)), len(versions), "one version per file")
	for _, v := range versions {
		require.Regexp(t, regexp.MustCompile(`^\d{14}$`), v)
	}

	sum, err := os.ReadFile("atlas.sum")
	require.NoError(t, err)
	for _, v := range versions {
		require.Contains(t, string(sum), v+"_", "atlas.sum lists the migration")
	}
}
