package service_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

// Step 12: new device and suspicious sign-in detection.

// fakeGeo: 203.0.113.x is France, 198.51.100.x is Japan, the rest unknown.
type fakeGeo struct{}

func (fakeGeo) Country(ip string) (string, string, bool) {
	switch {
	case strings.HasPrefix(ip, "203.0.113."):
		return "FR", "France", true
	case strings.HasPrefix(ip, "198.51.100."):
		return "JP", "Japan", true
	}
	return "", "", false
}

var day0 = time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC) // a Tuesday, 09:00 UTC

// history builds n past sign-ins, one per day at 09:00 from the same
// browser and home network in France.
func history(n int) []*domain.Session {
	out := make([]*domain.Session, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &domain.Session{
			ID: fmt.Sprintf("old-%d", i), UserID: "u1", RealmID: "r1",
			CreatedAt:         day0.AddDate(0, 0, i),
			IPAddress:         "203.0.113.10",
			DeviceFingerprint: "laptop",
		})
	}
	return out
}

func login(at time.Time, ip, device string) *domain.Session {
	return &domain.Session{ID: "new", UserID: "u1", RealmID: "r1", CreatedAt: at, IPAddress: ip, DeviceFingerprint: device, UserAgent: "Firefox/140"}
}

func TestAnalyzeLogin(t *testing.T) {
	usual := day0.AddDate(0, 0, 20) // 09:00, like every day

	t.Run("first sign-in: nothing to compare with", func(t *testing.T) {
		a := service.AnalyzeLogin(login(usual, "203.0.113.10", "laptop"), nil, fakeGeo{})
		require.True(t, a.FirstLogin)
		require.False(t, a.NewDevice)
		require.False(t, a.Suspicious())
	})

	t.Run("usual sign-in", func(t *testing.T) {
		a := service.AnalyzeLogin(login(usual, "203.0.113.10", "laptop"), history(15), fakeGeo{})
		require.False(t, a.NewDevice)
		require.False(t, a.NewNetwork)
		require.False(t, a.Suspicious())
		require.Equal(t, "FR", a.CountryCode)
	})

	t.Run("the current session in the history is ignored", func(t *testing.T) {
		cur := login(usual, "203.0.113.10", "phone")
		a := service.AnalyzeLogin(cur, append(history(3), cur), fakeGeo{})
		require.True(t, a.NewDevice)
	})

	t.Run("new device on the usual network: new device, not suspicious", func(t *testing.T) {
		a := service.AnalyzeLogin(login(usual, "203.0.113.77", "phone"), history(15), fakeGeo{})
		require.True(t, a.NewDevice)
		require.False(t, a.NewNetwork, "same /24")
		require.False(t, a.Suspicious())
	})

	t.Run("new device on a new network: suspicious", func(t *testing.T) {
		a := service.AnalyzeLogin(login(usual, "192.0.2.50", "phone"), history(15), nil)
		require.True(t, a.NewDevice)
		require.True(t, a.NewNetwork)
		require.Equal(t, []string{domain.SuspiciousNewNetworkAndDevice}, a.Reasons)
	})

	t.Run("new country", func(t *testing.T) {
		a := service.AnalyzeLogin(login(usual, "198.51.100.3", "laptop"), history(15), fakeGeo{})
		require.Equal(t, "JP", a.CountryCode)
		require.Contains(t, a.Reasons, domain.SuspiciousNewCountry)
	})

	t.Run("no country signal without GeoIP", func(t *testing.T) {
		a := service.AnalyzeLogin(login(usual, "198.51.100.3", "laptop"), history(15), nil)
		require.NotContains(t, a.Reasons, domain.SuspiciousNewCountry)
		require.Empty(t, a.CountryCode)
	})

	t.Run("unusual hour, with enough history", func(t *testing.T) {
		at3am := time.Date(2026, 9, 25, 3, 0, 0, 0, time.UTC)
		a := service.AnalyzeLogin(login(at3am, "203.0.113.10", "laptop"), history(15), fakeGeo{})
		require.Equal(t, []string{domain.SuspiciousUnusualHour}, a.Reasons)

		near := time.Date(2026, 9, 25, 11, 0, 0, 0, time.UTC) // 2 h from 09:00: still usual
		a = service.AnalyzeLogin(login(near, "203.0.113.10", "laptop"), history(15), fakeGeo{})
		require.False(t, a.Suspicious())

		a = service.AnalyzeLogin(login(at3am, "203.0.113.10", "laptop"), history(5), fakeGeo{})
		require.False(t, a.Suspicious(), "5 past sign-ins are not enough to know the usual hours")
	})

	t.Run("hours wrap around midnight", func(t *testing.T) {
		h := history(12)
		for _, s := range h {
			s.CreatedAt = time.Date(s.CreatedAt.Year(), s.CreatedAt.Month(), s.CreatedAt.Day(), 23, 30, 0, 0, time.UTC)
		}
		at1am := time.Date(2026, 9, 26, 1, 0, 0, 0, time.UTC)
		a := service.AnalyzeLogin(login(at1am, "203.0.113.10", "laptop"), h, nil)
		require.False(t, a.Suspicious(), "01:00 is 2 h after 23:00")
	})

	t.Run("IPv6 networks are /48", func(t *testing.T) {
		h := history(3)
		for _, s := range h {
			s.IPAddress = "2001:db8:aaaa:1::10"
		}
		same := service.AnalyzeLogin(login(usual, "2001:db8:aaaa:2::99", "phone"), h, nil)
		require.False(t, same.NewNetwork)
		other := service.AnalyzeLogin(login(usual, "2001:db8:bbbb::1", "phone"), h, nil)
		require.True(t, other.NewNetwork)
	})
}

func TestLoginSecurity_RecordsAndNotifies(t *testing.T) {
	ctx := context.Background()
	newSvc := func() (*service.LoginSecurityService, *memSessionHistory, *fakeAuditRepo, *recordingNotifier) {
		hist := &memSessionHistory{}
		for _, s := range history(15) {
			hist.add(s)
		}
		audit, notifier := &fakeAuditRepo{}, &recordingNotifier{}
		svc := service.NewLoginSecurityService(service.LoginSecurityDeps{
			Sessions: hist, Audit: audit, Notifier: notifier, GeoIP: fakeGeo{}, Synchronous: true,
		})
		return svc, hist, audit, notifier
	}
	usual := day0.AddDate(0, 0, 20)

	t.Run("usual sign-in: nothing written, nothing sent", func(t *testing.T) {
		svc, _, audit, notifier := newSvc()
		svc.SessionCreated(ctx, login(usual, "203.0.113.10", "laptop"))
		require.Empty(t, audit.actions())
		require.Empty(t, notifier.kinds())
	})

	t.Run("new device", func(t *testing.T) {
		svc, _, audit, notifier := newSvc()
		svc.SessionCreated(ctx, login(usual, "203.0.113.10", "phone"))
		require.Equal(t, []string{"new_device_login"}, audit.actions())
		require.Equal(t, domain.AuditLogInfo, audit.entries[0].Level)
		require.Equal(t, []domain.NotificationKind{domain.NotificationNewDeviceLogin}, notifier.kinds())
	})

	t.Run("suspicious: AuditLog level suspicious, event with reasons", func(t *testing.T) {
		svc, _, audit, notifier := newSvc()
		svc.SessionCreated(ctx, login(usual, "198.51.100.3", "phone"))
		require.Equal(t, []string{"suspicious_login"}, audit.actions())
		require.Equal(t, domain.AuditLogSuspicious, audit.entries[0].Level)
		e := notifier.last()
		require.Equal(t, domain.NotificationSuspiciousLogin, e.Kind)
		require.True(t, e.NewDevice, "the dispatcher falls back to the new-device e-mail when suspicious e-mails are off")
		require.Equal(t, "Japan", e.CountryName)
		require.ElementsMatch(t, []string{domain.SuspiciousNewCountry, domain.SuspiciousNewNetworkAndDevice}, e.SuspiciousReasons)
	})

	t.Run("wired into SessionService.Create", func(t *testing.T) {
		svc, _, audit, _ := newSvc()
		clock := newTestClock()
		sessions := service.NewSessionService(&fakeSessionRepo{now: clock.Now, byID: map[string]*domain.Session{}},
			fakeSettingsRepo{}, &fakeTokenRepo{byJTI: map[string]*domain.Token{}}, fakeSessionCache{},
			service.WithClock(clock.Now), service.WithLoginObserver(svc))
		_, _, err := sessions.Create(ctx, service.CreateSessionInput{RealmID: "r1", UserID: "u1", IPAddress: "198.51.100.3"})
		require.NoError(t, err)
		// No device fingerprint given: only the new country counts.
		require.Equal(t, []string{"suspicious_login"}, audit.actions())
	})
}

func TestDeviceFingerprint(t *testing.T) {
	require.Empty(t, service.DeviceFingerprint(""))
	a := service.DeviceFingerprint("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	require.Len(t, a, 64)
	require.Equal(t, a, service.DeviceFingerprint("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	require.NotEqual(t, a, service.DeviceFingerprint("ABCDEFGHIJKLMNOPQRSTUVWXY2"))
}
