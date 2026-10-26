package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


type GeoIPResolver interface {
	// Country returns the ISO 3166-1 code and English name, ok=false when
	// unknown (private address, address missing from the database).
	Country(ip string) (code, name string, ok bool)
}

const (
	loginHistoryWindow = 90 * 24 * time.Hour
	loginHistoryLimit  = 100
	// usualHourMinHistory: judging "unusual hour" needs enough history.
	usualHourMinHistory = 10
	usualHourMargin     = 2 // hours on each side
)

// LoginAnalysis is the verdict on one sign-in.
type LoginAnalysis struct {
	FirstLogin  bool // nothing to compare with
	NewDevice   bool
	NewNetwork  bool
	CountryCode string
	CountryName string
	// Reasons it looks suspicious (domain.Suspicious*); empty = normal.
	Reasons []string
}

// Suspicious tells whether at least one reason was found.
func (a LoginAnalysis) Suspicious() bool { return len(a.Reasons) > 0 }

// LoginSecurityService implements LoginObserver.
type LoginSecurityService struct {
	sessions repository.SessionRepository
	audit    repository.AuditLogRepository
	notifier Notifier
	geo      GeoIPResolver
	logger   *slog.Logger
	sync     bool
	sem      chan struct{}
}

// LoginSecurityDeps groups the dependencies of NewLoginSecurityService.
type LoginSecurityDeps struct {
	Sessions repository.SessionRepository
	Audit    repository.AuditLogRepository // optional
	Notifier Notifier                      // optional
	GeoIP    GeoIPResolver                 // optional: no "new country" signal without it
	Logger   *slog.Logger                  // optional
	// Synchronous runs the analysis inside SessionCreated (tests). By
	// default it runs in the background and never slows a sign-in.
	Synchronous bool
}

func NewLoginSecurityService(d LoginSecurityDeps) *LoginSecurityService {
	s := &LoginSecurityService{
		sessions: d.Sessions,
		audit:    d.Audit,
		notifier: d.Notifier,
		geo:      d.GeoIP,
		logger:   d.Logger,
		sync:     d.Synchronous,
		sem:      make(chan struct{}, 16),
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.notifier == nil {
		s.notifier = NopNotifier{}
	}
	return s
}

// SessionCreated is called by SessionService.Create.
func (s *LoginSecurityService) SessionCreated(ctx context.Context, sess *domain.Session) {
	if s.sync {
		if _, err := s.Analyze(ctx, sess); err != nil {
			s.logger.WarnContext(ctx, "login analysis failed", "session_id", sess.ID, "error", err)
		}
		return
	}
	ctx = context.WithoutCancel(ctx)
	select {
	case s.sem <- struct{}{}:
	default:
		s.logger.WarnContext(ctx, "login analysis skipped: too many in progress", "session_id", sess.ID)
		return
	}
	go func() {
		defer func() { <-s.sem }()
		if _, err := s.Analyze(ctx, sess); err != nil {
			s.logger.WarnContext(ctx, "login analysis failed", "session_id", sess.ID, "error", err)
		}
	}()
}

// Analyze compares sess with the user's history, then writes the AuditLog
// entry and sends the event to the notifier.
func (s *LoginSecurityService) Analyze(ctx context.Context, sess *domain.Session) (LoginAnalysis, error) {
	history, err := s.sessions.ListRecentByUser(ctx, sess.UserID, sess.CreatedAt.Add(-loginHistoryWindow), loginHistoryLimit+1)
	if err != nil {
		return LoginAnalysis{}, fmt.Errorf("login analysis: history: %w", err)
	}
	a := AnalyzeLogin(sess, history, s.geo)
	s.record(ctx, sess, a)
	return a, nil
}

func (s *LoginSecurityService) record(ctx context.Context, sess *domain.Session, a LoginAnalysis) {
	var (
		action string
		level  domain.AuditLogLevel
		kind   domain.NotificationKind
	)
	switch {
	case a.Suspicious():
		action, level, kind = "suspicious_login", domain.AuditLogSuspicious, domain.NotificationSuspiciousLogin
	case a.NewDevice:
		action, level, kind = "new_device_login", domain.AuditLogInfo, domain.NotificationNewDeviceLogin
	default:
		return
	}

	if s.audit != nil {
		details := map[string]interface{}{
			"new_device":  a.NewDevice,
			"new_network": a.NewNetwork,
		}
		if a.CountryCode != "" {
			details["country"] = a.CountryCode
		}
		if len(a.Reasons) > 0 {
			details["reasons"] = a.Reasons
		}
		_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
			RealmID:      sess.RealmID,
			UserID:       sess.UserID,
			Action:       action,
			ResourceType: "Session",
			ResourceID:   sess.ID,
			IPAddress:    sess.IPAddress,
			UserAgent:    sess.UserAgent,
			Level:        level,
			Status:       domain.AuditLogSuccess,
			Details:      details,
		})
	}
	s.notifier.Notify(ctx, domain.NotificationEvent{
		Kind:              kind,
		RealmID:           sess.RealmID,
		UserID:            sess.UserID,
		OccurredAt:        sess.CreatedAt,
		IPAddress:         sess.IPAddress,
		UserAgent:         sess.UserAgent,
		SessionID:         sess.ID,
		CountryCode:       a.CountryCode,
		CountryName:       a.CountryName,
		SuspiciousReasons: a.Reasons,
		NewDevice:         a.NewDevice,
	})
}

// AnalyzeLogin is the pure decision: cur against the user's past sessions
// (cur itself may be in history, it is skipped). geo may be nil.
func AnalyzeLogin(cur *domain.Session, history []*domain.Session, geo GeoIPResolver) LoginAnalysis {
	var a LoginAnalysis
	if geo != nil {
		a.CountryCode, a.CountryName, _ = geo.Country(cur.IPAddress)
	}

	past := make([]*domain.Session, 0, len(history))
	for _, h := range history {
		if h.ID != cur.ID {
			past = append(past, h)
		}
	}
	if len(past) == 0 {
		a.FirstLogin = true
		return a
	}

	// New device. A session without fingerprint (created outside the login
	// page) cannot be judged.
	if cur.DeviceFingerprint != "" {
		a.NewDevice = true
		for _, p := range past {
			if p.DeviceFingerprint == cur.DeviceFingerprint {
				a.NewDevice = false
				break
			}
		}
	}

	// New network.
	if network, ok := ipNetwork(cur.IPAddress); ok {
		a.NewNetwork = true
		for _, p := range past {
			if pn, ok := ipNetwork(p.IPAddress); ok && pn == network {
				a.NewNetwork = false
				break
			}
		}
	}

	// New country: only when we know the country now AND at least once before.
	if a.CountryCode != "" {
		seen := map[string]bool{}
		for _, p := range past {
			if code, _, ok := geo.Country(p.IPAddress); ok {
				seen[code] = true
			}
		}
		if len(seen) > 0 && !seen[a.CountryCode] {
			a.Reasons = append(a.Reasons, domain.SuspiciousNewCountry)
		}
	}

	// Unusual hour (UTC on both sides, so time zones do not matter).
	if len(past) >= usualHourMinHistory {
		h := cur.CreatedAt.UTC().Hour()
		usual := false
		for _, p := range past {
			if hourDistance(p.CreatedAt.UTC().Hour(), h) <= usualHourMargin {
				usual = true
				break
			}
		}
		if !usual {
			a.Reasons = append(a.Reasons, domain.SuspiciousUnusualHour)
		}
	}

	if a.NewDevice && a.NewNetwork {
		a.Reasons = append(a.Reasons, domain.SuspiciousNewNetworkAndDevice)
	}
	return a
}

// ipNetwork groups addresses the way they are usually handed out: an IPv4
// /24 (a home or office), an IPv6 /48 (one site).
func ipNetwork(ip string) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// hourDistance on a 24 h clock: 23 h and 1 h are 2 hours apart.
func hourDistance(a, b int) int {
	d := a - b
	if d < 0 {
		d = -d
	}
	if d > 12 {
		d = 24 - d
	}
	return d
}
