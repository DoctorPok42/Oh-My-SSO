package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListVersions(t *testing.T) {
	require.Equal(t, "1", listVersions([]string{"1"}))
	require.Equal(t, "1, 2, 3", listVersions([]string{"1", "2", "3"}))
	require.Equal(t, "1, 2, 3, and 2 more", listVersions([]string{"1", "2", "3", "4", "5"}))
}
