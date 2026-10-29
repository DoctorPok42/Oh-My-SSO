package main

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseLength(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30m": 30 * time.Minute, "2h": 2 * time.Hour, "1h30m": 90 * time.Minute, "7d": 7 * 24 * time.Hour, "1d": 24 * time.Hour,
	} {
		got, err := parseLength(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "0", "-1h", "0d", "-2d", "xd", "1w", "tomorrow"} {
		_, err := parseLength(bad)
		var ue usageError
		require.True(t, errors.As(err, &ue), "%q: want a usage error, got %v", bad, err)
	}
}

func TestParseCLITime(t *testing.T) {
	want := time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	for _, in := range []string{"2026-11-02T18:00:00Z", "2026-11-02T19:00:00+01:00", "2026-11-02 18:00", "2026-11-02T18:00"} {
		got, err := parseCLITime("until", in)
		require.NoError(t, err, in)
		require.True(t, want.Equal(got), "%s: %s", in, got)
	}
	got, err := parseCLITime("until", "2026-11-02")
	require.NoError(t, err)
	require.True(t, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC).Equal(got))

	got, err = parseCLITime("from", "")
	require.NoError(t, err)
	require.True(t, got.IsZero(), "empty: now (zero)")

	_, err = parseCLITime("until", "next monday")
	var ue usageError
	require.ErrorAs(t, err, &ue)
	require.Contains(t, ue.msg, "--until")
}

func TestOneLine(t *testing.T) {
	require.Equal(t, "a b c", oneLine("a\n b\tc", 40))
	require.Equal(t, "abcd…", oneLine("abcdefgh", 5))
	require.Equal(t, "no end (until lifted)", endLabel(time.Time{}))
}
