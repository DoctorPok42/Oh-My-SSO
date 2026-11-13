package service_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

func TestIPAllowed(t *testing.T) {
	list := []string{"10.0.0.0/8", " 192.0.2.7 ", "2001:db8::/32", "172.16.5.9/16", "::ffff:198.51.100.0/120"}
	for ip, want := range map[string]bool{
		"10.1.2.3":        true,
		"192.0.2.7":       true,
		"192.0.2.8":       false,
		"2001:db8:1::5":   true,
		"2001:db9::1":     false,
		"::ffff:10.9.9.9": true, // IPv4-mapped client address
		"172.16.200.1":    true, // 172.16.5.9/16 is the network 172.16.0.0/16, as net.ParseCIDR reads it
		"172.17.0.1":      false,
		"198.51.100.42":   true,  // IPv4-mapped entry
		"":                false, // unknown address: in no list
		"not-an-address":  false,
		"fe80::1%eth0":    false,
		"203.0.113.1":     false,
		"::1":             false,
	} {
		require.Equal(t, want, service.IPAllowed(list, ip), ip)
	}

	require.True(t, service.IPAllowed(nil, "203.0.113.1"), "no list: every address")
	require.True(t, service.IPAllowed([]string{" ", ""}, ""), "blank entries only: no list")
	require.False(t, service.IPAllowed([]string{"garbage"}, "203.0.113.1"), "an unreadable entry keeps the list closed")
}

// netSettings is the settings repository of one realm; err makes it fail.
type netSettings struct {
	repository.InstanceSettingsRepository
	allow []string
	err   error
	reads atomic.Int32
}

func (s *netSettings) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	s.reads.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	if s.allow == nil {
		return nil, repository.ErrNotFound
	}
	st := service.DefaultInstanceSettings(realmID)
	st.IPAllowlist = s.allow
	return st, nil
}

func TestSignInNetwork_Allows(t *testing.T) {
	ctx := context.Background()

	t.Run("no settings row: open", func(t *testing.T) {
		n := service.NewSignInNetworkService(&netSettings{}, nil)
		ok, err := n.Allows(ctx, "r1", "203.0.113.1")
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("a list: only its addresses", func(t *testing.T) {
		repo := &netSettings{allow: []string{"10.0.0.0/8"}}
		n := service.NewSignInNetworkService(repo, nil)
		ok, err := n.Allows(ctx, "r1", "10.4.4.4")
		require.NoError(t, err)
		require.True(t, ok)
		ok, err = n.Allows(ctx, "r1", "203.0.113.1")
		require.NoError(t, err)
		require.False(t, ok)
		require.EqualValues(t, 1, repo.reads.Load(), "read once, then cached for a minute")
	})

	t.Run("database error: refused, never the open defaults", func(t *testing.T) {
		repo := &netSettings{err: errors.New("connection refused")}
		n := service.NewSignInNetworkService(repo, nil)
		for range 2 {
			ok, err := n.Allows(ctx, "r1", "10.4.4.4")
			require.Error(t, err)
			require.False(t, ok)
		}
		require.EqualValues(t, 2, repo.reads.Load(), "an error is not cached: the next sign-in asks again")

		// The database is back: the list applies at once.
		repo.err, repo.allow = nil, []string{"192.0.2.0/24"}
		ok, err := n.Allows(ctx, "r1", "10.4.4.4")
		require.NoError(t, err)
		require.False(t, ok)
	})
}
