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

// newMethodGrace: a factor added less than this ago is expected to be used
// for the first time soon (the user just set it up), not suspicious.
const newMethodGrace = 30 * 24 * time.Hour

// LoginAnalysis is the verdict on one sign-in.
type LoginAnalysis struct {
	FirstLogin  bool // nothing to compare with
	NewDevice   bool
	NewNetwork  bool
	CountryCode string
	CountryName string
	// NewSignInMethod: the factor type of this sign-in when the user has not
	// used it in the history window while using other ones (Step 18c).
	NewSignInMethod string
	// Reasons it looks suspicious (domain.Suspicious*); empty = normal.
	Reasons []string
}

// Suspicious tells whether at least one reason was found.
func (a LoginAnalysis) Suspicious() bool { return len(a.Reasons) > 0 }

// LoginSecurityService implements LoginObserver.
type LoginSecurityService struct {
	sessions repository.SessionRepository
	methods  repository.MfaMethodRepository
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
	// Methods (optional): the user's factors, so that the first use of a
	// newly added one is not "a sign-in method never used".
	Methods  repository.MfaMethodRepository
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
		methods:  d.Methods,
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
	var factors []*domain.MfaMethod
	if s.methods != nil && signInMethod(sess) != "" {
		if factors, err = s.methods.ListByUser(ctx, sess.UserID); err != nil {
			return LoginAnalysis{}, fmt.Errorf("login analysis: factors: %w", err)
		}
	}
	a := AnalyzeLoginWithFactors(sess, history, s.geo, factors)
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
		if sess.RememberMe {
			// A long-lived session on an unusual device is worth knowing about.
			details["remember_me"] = true
		}
		if a.NewSignInMethod != "" {
			details["sign_in_method"] = a.NewSignInMethod
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
		MfaMethodType:     domain.MfaMethodType(a.NewSignInMethod),
	})
}

// SignInRisk (LoginRiskChecker) judges a sign-in before it happens, with
// the rules of Analyze: on a trusted device, a sign-in that looks
// suspicious asks for the second factor again (Step 18d).
func (s *LoginSecurityService) SignInRisk(ctx context.Context, candidate *domain.Session) ([]string, error) {
	history, err := s.sessions.ListRecentByUser(ctx, candidate.UserID, candidate.CreatedAt.Add(-loginHistoryWindow), loginHistoryLimit+1)
	if err != nil {
		return nil, fmt.Errorf("sign-in risk: history: %w", err)
	}
	return AnalyzeLogin(candidate, history, s.geo).Reasons, nil
}

// AnalyzeLogin is the pure decision: cur against the user's past sessions
// (cur itself may be in history, it is skipped). geo may be nil.
func AnalyzeLogin(cur *domain.Session, history []*domain.Session, geo GeoIPResolver) LoginAnalysis {
	return AnalyzeLoginWithFactors(cur, history, geo, nil)
}

// AnalyzeLoginWithFactors is AnalyzeLogin knowing the user's factors (their
// creation dates): a factor added less than newMethodGrace ago may be used
// for the first time without being suspicious. factors may be nil.
func AnalyzeLoginWithFactors(cur *domain.Session, history []*domain.Session, geo GeoIPResolver, factors []*domain.MfaMethod) LoginAnalysis {
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

	if isNewSignInMethod(cur, past, factors) {
		a.NewSignInMethod = signInMethod(cur)
		a.Reasons = append(a.Reasons, domain.SuspiciousNewSignInMethod)
	}
	return a
}

// signInMethod is the factor that proved a sign-in besides the password, or
// the passkey of a sign-in without password ("" for a password alone). A
// step-up updates it on the stored session: a factor used for a step-up
// counts as used.
func signInMethod(s *domain.Session) string {
	if !s.MFAVerified {
		return ""
	}
	return s.MFAMethodType
}

// isNewSignInMethod: cur uses a factor type that none of the past sessions
// used, while some of them used another factor. The user suddenly signs in
// another way: a backup code instead of the usual authenticator app, a
// security key nobody saw before... A user whose history has no factor at
// all (their first one) and a factor added recently are not suspicious.
func isNewSignInMethod(cur *domain.Session, past []*domain.Session, factors []*domain.MfaMethod) bool {
	m := signInMethod(cur)
	if m == "" {
		return false
	}
	usesFactors := false
	for _, p := range past {
		pm := signInMethod(p)
		if pm == m {
			return false
		}
		if pm != "" {
			usesFactors = true
		}
	}
	if !usesFactors {
		return false
	}
	for _, f := range factors {
		if string(f.Type) == m && cur.CreatedAt.Sub(f.CreatedAt) < newMethodGrace {
			return false
		}
	}
	return true
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
