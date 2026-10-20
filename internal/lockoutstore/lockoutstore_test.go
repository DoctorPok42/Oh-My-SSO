package lockoutstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/lockoutstore"
)

func TestEncodeDecode(t *testing.T) {
	require.Equal(t, "", lockoutstore.Encode(domain.LockoutState{}))

	now := time.Date(2026, 10, 19, 9, 30, 0, 123_000_000, time.UTC)
	st := domain.LockoutState{FailedCount: 2, LastFailedAt: now, LockedUntil: now.Add(time.Minute), LockCount: 1, LastLockedAt: now}
	raw := lockoutstore.Encode(st)
	back, err := lockoutstore.Decode(raw)
	require.NoError(t, err)
	require.Equal(t, raw, lockoutstore.Encode(back), "encode(decode(x)) == x: the compare-and-swap compares strings")
	require.True(t, back.LockedUntil.Equal(st.LockedUntil))
	require.Equal(t, 2, back.FailedCount)

	_, err = lockoutstore.Decode("{not json")
	require.Error(t, err)
}

func TestMemory(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	m := lockoutstore.NewMemory(clock)

	st, err := m.Get(ctx, "k")
	require.NoError(t, err)
	require.True(t, st.IsZero())

	one := domain.LockoutState{FailedCount: 1, LastFailedAt: now}
	ok, err := m.CompareAndSwap(ctx, "k", domain.LockoutState{}, one, time.Hour)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = m.CompareAndSwap(ctx, "k", domain.LockoutState{}, domain.LockoutState{FailedCount: 7}, time.Hour)
	require.NoError(t, err)
	require.False(t, ok, "stale old value")

	got, err := m.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, 1, got.FailedCount)

	now = now.Add(2 * time.Hour) // TTL over
	got, err = m.Get(ctx, "k")
	require.NoError(t, err)
	require.True(t, got.IsZero())
}
