package service_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/service"
)

func TestIsDeviceID(t *testing.T) {
	ok := strings.Repeat("A", 13) + "Z2347XYQ7ABCD" // 26 base32 characters
	require.Len(t, ok, 26)
	require.True(t, service.IsDeviceID(ok))

	for name, v := range map[string]string{
		"too short":            ok[:25],
		"too long":             ok + "A",
		"lower case":           strings.ToLower(ok),
		"digit 0 (not base32)": ok[:25] + "0",
		"digit 1 (not base32)": ok[:25] + "1",
		"digit 8 (not base32)": ok[:25] + "8",
		"symbol":               ok[:25] + "=",
		"empty":                "",
	} {
		require.False(t, service.IsDeviceID(v), name)
	}
}
