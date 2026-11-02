package audit_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
)

func TestCatalog_NamesAreUniqueAndWellFormed(t *testing.T) {
	name := regexp.MustCompile(`^[a-z_]+\.[a-z_]+$`)
	seen := map[string]bool{}
	for _, a := range audit.Catalog {
		require.Regexp(t, name, a.Name, "action names are <domain>.<what happened>")
		require.False(t, seen[a.Name], "%s listed twice", a.Name)
		require.NotEmpty(t, a.Category, a.Name)
		require.NotEmpty(t, a.Label, a.Name)
		seen[a.Name] = true
	}
	require.True(t, audit.Known(audit.AuthLogin))
	require.False(t, audit.Known("admin.client.update"), "old names are gone")
}
