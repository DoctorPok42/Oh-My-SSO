package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/sessioncache"
)

var ErrSessionInvalid = core.ErrSessionInvalid // alias: same variable as core
var ErrReauthRequired = errors.New("service: reauthentication required for this app")
var ErrClientSessionLimitTooLong = errors.New("service: app session limit exceeds realm limit")

const (
	// Aligned https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#introduction
	defaultSessionMaxLifetime = 8 * time.Hour
	defaultSessionIdleTimeout = 10 * time.Minute

	// "Keep me signed in". 30 days is the NIST SP 800-63B-4 ceiling for
	// reauthentication at AAL1; the idle timeout ends a session forgotten
	// on a device. https://pages.nist.gov/800-63-4/sp800-63b/aal
	defaultRememberMeMaxDays  = 30
	defaultRememberMeIdleDays = 7
	// maxRememberMeDays: browsers cap a cookie's lifetime at 400 days.
	maxRememberMeDays = 365

	touchInterval  = time.Minute
	policyCacheTTL = time.Minute
)

type SessionService struct {
	sessions repository.SessionRepository
	settings repository.InstanceSettingsRepository
	tokens   repository.TokenRepository // revoked in cascade with their session
	cache    sessioncache.Cache
	now      func() time.Time
	logger   *slog.Logger

	policyMu    sync.Mutex
	policyCache map[string]cachedPolicy

	observers []LoginObserver
	audit     repository.AuditLogRepository // nil: sign-outs are not audited
	revokers  []RevocationObserver
}

// RevocationObserver is told when every session of a user is revoked
// (password reset, MFA reset, an admin, a suspension): the trusted devices
// of Step 18d end there too.
type RevocationObserver interface {
	AllSessionsRevoked(ctx context.Context, userID string, reason domain.SessionRevokedReason)
}

// WithRevocationObserver adds o to the observers of RevokeAllForUser.
func WithRevocationObserver(o RevocationObserver) SessionOption {
	return func(s *SessionService) { s.revokers = append(s.revokers, o) }
}

type LoginObserver interface {
	SessionCreated(ctx context.Context, sess *domain.Session)
}

// WithLoginObserver plugs a LoginObserver into Create. Several can be
// plugged: they are called in order.
func WithLoginObserver(o LoginObserver) SessionOption {
	return func(s *SessionService) { s.observers = append(s.observers, o) }
}

// WithAuditLog records the sign-outs the users ask for (EndSession, Logout)
// in the audit log.
func WithAuditLog(a repository.AuditLogRepository) SessionOption {
	return func(s *SessionService) { s.audit = a }
}

type cachedPolicy struct {
	policy    sessionPolicy
	fetchedAt time.Time
}

type SessionOption func(*SessionService)

func WithClock(now func() time.Time) SessionOption {
	return func(s *SessionService) { s.now = now }
}

func WithLogger(l *slog.Logger) SessionOption {
	return func(s *SessionService) { s.logger = l }
}

func NewSessionService(
	sessions repository.SessionRepository,
	settings repository.InstanceSettingsRepository,
	tokens repository.TokenRepository,
	cache sessioncache.Cache,
	opts ...SessionOption,
) *SessionService {
	s := &SessionService{
		sessions:    sessions,
		settings:    settings,
		tokens:      tokens,
		cache:       cache,
		now:         time.Now,
		logger:      slog.Default(),
		policyCache: make(map[string]cachedPolicy),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type CreateSessionInput struct {
	RealmID       string
	UserID        string
	IPAddress     string
	UserAgent     string
	AuthMethod    string
	MFAVerified   bool
	MFAMethodType string
	// MFAVerifiedAt defaults to "now" when MFAVerified is true.
	MFAVerifiedAt time.Time
	DeviceFingerprint string
	// RememberMe asks for a remembered session ("Keep me signed in"). It is
	// ignored when the realm does not allow it: check the RememberMe field
	// of the session that Create returns.
	RememberMe bool
	// TrustedDevice: the second factor was skipped on a trusted device.
	TrustedDevice bool
}

// DeviceFingerprint turns the random id of the sso_device cookie into what
// sessions store: its SHA-256, like every other token we keep. "" stays "".
func DeviceFingerprint(deviceID string) string {
	if deviceID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("device:" + deviceID))
	return hex.EncodeToString(sum[:])
}

func (s *SessionService) Create(ctx context.Context, in CreateSessionInput) (rawToken string, sess *domain.Session, err error) {
	policy := s.policy(ctx, in.RealmID)

	rawToken = rand.Text()
	authMethod := in.AuthMethod
	if authMethod == "" {
		authMethod = domain.AuthMethodPassword
	}
	mfaAt := in.MFAVerifiedAt
	if in.MFAVerified && mfaAt.IsZero() {
		mfaAt = s.now()
	}

	remember := in.RememberMe && policy.rememberMe
	lifetime := policy.MaxLifetime
	if remember {
		lifetime = policy.RememberMeMaxLifetime
	}

	now := s.now()
	sess, err = s.sessions.Create(ctx, repository.CreateSessionParams{
		CreatedAt:         now,
		TokenHash:         HashSessionToken(rawToken),
		RealmID:           in.RealmID,
		UserID:            in.UserID,
		ExpiresAt:         now.Add(lifetime),
		RememberMe:        remember,
		IPAddress:         in.IPAddress,
		UserAgent:         in.UserAgent,
		MFAVerified:       in.MFAVerified,
		MFAMethodType:     in.MFAMethodType,
		MFAVerifiedAt:     mfaAt,
		AuthMethod:        authMethod,
		DeviceFingerprint: in.DeviceFingerprint,
		TrustedDevice:     in.TrustedDevice && !in.MFAVerified,
	})
	if err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}

	for _, o := range s.observers {
		o.SessionCreated(ctx, sess)
	}
	return rawToken, sess, nil
}

type ClientSessionLimits struct {
	IdleTimeout time.Duration
	MaxLifetime time.Duration
}

func ClientSessionLimitsFromMinutes(idleMinutes, maxMinutes *int) ClientSessionLimits {
	var l ClientSessionLimits
	if idleMinutes != nil && *idleMinutes > 0 {
		l.IdleTimeout = time.Duration(*idleMinutes) * time.Minute
	}
	if maxMinutes != nil && *maxMinutes > 0 {
		l.MaxLifetime = time.Duration(*maxMinutes) * time.Minute
	}
	return l
}

func (s *SessionService) CheckClientSessionLimits(ctx context.Context, realmID string, limits ClientSessionLimits) error {
	policy := s.policy(ctx, realmID)
	if limits.IdleTimeout > policy.IdleTimeout {
		return fmt.Errorf("%w: idle %s > realm %s", ErrClientSessionLimitTooLong, limits.IdleTimeout, policy.IdleTimeout)
	}
	if limits.MaxLifetime > policy.MaxLifetime {
		return fmt.Errorf("%w: max %s > realm %s", ErrClientSessionLimitTooLong, limits.MaxLifetime, policy.MaxLifetime)
	}
	return nil
}

func (s *SessionService) Validate(ctx context.Context, realmID, rawToken string) (*domain.Session, error) {
	return s.validate(ctx, realmID, rawToken, ClientSessionLimits{})
}

func (s *SessionService) ValidateForClient(ctx context.Context, realmID, rawToken string, limits ClientSessionLimits) (*domain.Session, error) {
	return s.validate(ctx, realmID, rawToken, limits)
}

func (s *SessionService) validate(ctx context.Context, realmID, rawToken string, limits ClientSessionLimits) (*domain.Session, error) {
	if rawToken == "" {
		return nil, ErrSessionInvalid
	}
	tokenHash := HashSessionToken(rawToken)

	sess, fromCache, err := s.lookup(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if sess.Status != domain.SessionActive {
		return nil, ErrSessionInvalid
	}

	if sess.RealmID != realmID {
		return nil, ErrSessionInvalid
	}

	now := s.now()
	policy := s.policy(ctx, realmID)

	if policy.Expired(sess, now) {
		s.expire(ctx, sess)
		return nil, ErrSessionInvalid
	}

	if limits.MaxLifetime > 0 && !now.Before(sess.CreatedAt.Add(limits.MaxLifetime)) {
		return nil, ErrReauthRequired
	}
	if limits.IdleTimeout > 0 && !now.Before(sess.LastActivityAt.Add(limits.IdleTimeout)) {
		return nil, ErrReauthRequired
	}

	if now.Sub(sess.LastActivityAt) >= touchInterval {
		s.touch(ctx, sess, now)
	}

	if !fromCache {
		s.fillCache(ctx, sess)
	}
	return sess, nil
}

// GetActive loads a session by its id, for back-channel calls (no cookie,
// e.g. the OIDC /token endpoint). Same validity rules as Validate, but it
// does not refresh last_activity_at: a server-to-server call is not a proof
// that the user is still active.
func (s *SessionService) GetActive(ctx context.Context, sessionID string) (*domain.Session, error) {
	if sessionID == "" {
		return nil, ErrSessionInvalid
	}
	sess, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrSessionInvalid
		}
		return nil, fmt.Errorf("get active session: %w", err)
	}
	if sess.Status != domain.SessionActive {
		return nil, ErrSessionInvalid
	}

	now := s.now()
	policy := s.policy(ctx, sess.RealmID)
	if policy.Expired(sess, now) {
		s.expire(ctx, sess)
		return nil, ErrSessionInvalid
	}
	return sess, nil
}

// RememberMeOption tells the sign-in page whether to offer "Keep me signed
// in" in this realm, and for how long a remembered session lasts at most.
func (s *SessionService) RememberMeOption(ctx context.Context, realmID string) (allowed bool, maxLifetime time.Duration) {
	p := s.policy(ctx, realmID)
	return p.rememberMe, p.RememberMeMaxLifetime
}

func (s *SessionService) TouchActive(ctx context.Context, sessionID string) (*domain.Session, error) {
	sess, err := s.GetActive(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	s.Touch(ctx, sess)
	return sess, nil
}

// Touch records activity on a session the caller has just validated with
// GetActive (the Admin API reads the session in parallel with its other
// checks, and records the activity once they all passed). Same rule as
// TouchActive: at most once per touchInterval.
func (s *SessionService) Touch(ctx context.Context, sess *domain.Session) {
	if now := s.now(); now.Sub(sess.LastActivityAt) >= touchInterval {
		s.touch(ctx, sess, now)
	}
}

// MarkMFAVerified upgrades an active session after a successful second
// factor (step-up, or first enrollment). The session keeps its id and its
// tokens; only mfa_verified, mfa_method_type and mfa_verified_at change.
//
// The cache is rewritten with the fresh values (update if present, create
// otherwise). If a concurrent request writes a stale copy afterwards, the
// worst case is "MFA not verified" until the next step-up: it fails closed,
// never open.
func (s *SessionService) MarkMFAVerified(ctx context.Context, sess *domain.Session, method string) (*domain.Session, error) {
	at := s.now()
	if err := s.sessions.MarkMFAVerified(ctx, sess.ID, method, at); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrSessionInvalid
		}
		return nil, fmt.Errorf("mark mfa verified: %w", err)
	}
	upd := *sess
	upd.MFAVerified = true
	upd.MFAMethodType = method
	upd.MFAVerifiedAt = at

	if upd.TokenHash != "" {
		entry := sessioncache.EntryFromSession(&upd)
		if err := s.cache.Refresh(ctx, upd.TokenHash, entry, s.ttl(&upd)); err != nil {
			s.logger.WarnContext(ctx, "session cache refresh failed", "session_id", upd.ID, "error", err)
		}
		if err := s.cache.Fill(ctx, upd.TokenHash, entry, s.ttl(&upd)); err != nil {
			s.logger.WarnContext(ctx, "session cache fill failed", "session_id", upd.ID, "error", err)
		}
	}
	return &upd, nil
}

func (s *SessionService) Revoke(ctx context.Context, sessionID string, reason domain.SessionRevokedReason) error {
	sess, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrSessionInvalid
		}
		return fmt.Errorf("revoke session: %w", err)
	}

	if err := s.sessions.Revoke(ctx, sess.ID, reason); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("revoke session: %w", err)
	}
	if err := s.markRevoked(ctx, sess); err != nil {
		return err
	}
	return s.revokeSessionTokens(ctx, sess.ID)
}

// LogoutEvent says how a user signed out, for the audit log.
type LogoutEvent struct {
	Via       domain.LogoutVia
	ClientID  string // client_id or entity ID that asked, if any
	IPAddress string
	UserAgent string
	Confirmed bool // answered "Sign out" on the confirmation page
}

// Logout ends the session of a browser (its raw cookie token). An unknown
// token is not an error: the browser is signed out either way.
func (s *SessionService) Logout(ctx context.Context, rawToken string, ev LogoutEvent) error {
	if rawToken == "" {
		return nil
	}
	sess, err := s.sessions.GetByTokenHash(ctx, HashSessionToken(rawToken))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("logout: %w", err)
	}
	return s.EndSession(ctx, sess, domain.SessionRevokedUserLogout, ev)
}

// EndSession revokes a session the user asked to leave (sign-out, another
// account signing in...) with its tokens, and records it in the audit log
// when the session was still active.
func (s *SessionService) EndSession(ctx context.Context, sess *domain.Session, reason domain.SessionRevokedReason, ev LogoutEvent) error {
	wasActive := sess.Status == domain.SessionActive
	if err := s.sessions.Revoke(ctx, sess.ID, reason); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("end session: %w", err)
	}
	if err := s.markRevoked(ctx, sess); err != nil {
		return err
	}
	if err := s.revokeSessionTokens(ctx, sess.ID); err != nil {
		return err
	}
	if wasActive {
		s.auditLogout(ctx, sess, ev)
	}
	return nil
}

func (s *SessionService) auditLogout(ctx context.Context, sess *domain.Session, ev LogoutEvent) {
	if s.audit == nil {
		return
	}
	details := map[string]interface{}{"via": string(ev.Via), "remember_me": sess.RememberMe}
	if ev.ClientID != "" {
		details["client_id"] = ev.ClientID
	}
	if ev.Confirmed {
		details["confirmed"] = true
	}
	if _, err := s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      sess.RealmID,
		UserID:       sess.UserID,
		Action:       "logout",
		ResourceType: "Session",
		ResourceID:   sess.ID,
		IPAddress:    ev.IPAddress,
		UserAgent:    ev.UserAgent,
		Level:        domain.AuditLogInfo,
		Status:       domain.AuditLogSuccess,
		Details:      details,
	}); err != nil {
		s.logger.WarnContext(ctx, "audit: record sign-out", "session_id", sess.ID, "error", err)
	}
}

func (s *SessionService) RevokeAllForUser(ctx context.Context, userID string, reason domain.SessionRevokedReason) error {
	revoked, err := s.sessions.RevokeAllByUser(ctx, userID, reason)
	if err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	for _, sess := range revoked {
		if err := s.markRevoked(ctx, sess); err != nil {
			return err
		}
		if err := s.revokeSessionTokens(ctx, sess.ID); err != nil {
			return err
		}
	}
	for _, o := range s.revokers {
		o.AllSessionsRevoked(ctx, userID, reason)
	}
	return nil
}

// revokeSessionTokens revokes every token issued for a session. A token must
// never outlive an explicit revocation of the session it was issued for.
// Idempotent: calling Revoke again after a partial failure finishes the job.
func (s *SessionService) revokeSessionTokens(ctx context.Context, sessionID string) error {
	toks, err := s.tokens.ListBySession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("revoke session tokens: %w", err)
	}
	for _, t := range toks {
		if t.Revoked {
			continue
		}
		if err := s.tokens.Revoke(ctx, t.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("revoke session tokens: token %s: %w", t.ID, err)
		}
	}
	return nil
}

func HashSessionToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// SessionDurations are the session lifetimes of one realm.
type SessionDurations struct {
	MaxLifetime time.Duration
	IdleTimeout time.Duration
	// RememberMe: the realm offers "Keep me signed in". A remembered session
	// lasts RememberMeMaxLifetime at most and ends after
	// RememberMeIdleTimeout without use.
	RememberMe            bool
	RememberMeMaxLifetime time.Duration
	RememberMeIdleTimeout time.Duration
}

// SessionDurationsOf reads the durations of a realm from its settings. nil
// (no settings row yet) gives the defaults, which are also what the admin
// console shows for such a realm. A zero or negative value falls back to its
// default.
func SessionDurationsOf(st *domain.InstanceSettings) SessionDurations {
	d := SessionDurations{
		MaxLifetime:           defaultSessionMaxLifetime,
		IdleTimeout:           defaultSessionIdleTimeout,
		RememberMe:            true,
		RememberMeMaxLifetime: defaultRememberMeMaxDays * 24 * time.Hour,
		RememberMeIdleTimeout: defaultRememberMeIdleDays * 24 * time.Hour,
	}
	if st == nil {
		return d
	}
	if st.SessionMaxHours > 0 {
		d.MaxLifetime = time.Duration(st.SessionMaxHours) * time.Hour
	}
	if st.SessionIdleMinutes > 0 {
		d.IdleTimeout = time.Duration(st.SessionIdleMinutes) * time.Minute
	}
	d.RememberMe = st.RememberMeEnabled
	if st.RememberMeMaxDays > 0 {
		d.RememberMeMaxLifetime = time.Duration(st.RememberMeMaxDays) * 24 * time.Hour
	}
	if st.RememberMeIdleDays > 0 {
		d.RememberMeIdleTimeout = time.Duration(st.RememberMeIdleDays) * 24 * time.Hour
	}
	return d
}

// Limits returns the idle timeout and the absolute end that apply to sess.
//
// A remembered session keeps its long durations only while the realm
// offers "Keep me signed in". Once an administrator turns the option off,
// it is held to the normal durations, counted from its creation: it fails
// closed, it never lasts longer than the realm now allows.
func (d SessionDurations) Limits(sess *domain.Session) (idle time.Duration, end time.Time) {
	if sess.RememberMe && d.RememberMe {
		return d.RememberMeIdleTimeout, sess.ExpiresAt
	}
	end = sess.ExpiresAt
	if normal := sess.CreatedAt.Add(d.MaxLifetime); sess.RememberMe && normal.Before(end) {
		end = normal
	}
	return d.IdleTimeout, end
}

// Expired: sess is past its absolute end, or was idle for too long.
func (d SessionDurations) Expired(sess *domain.Session, now time.Time) bool {
	idle, end := d.Limits(sess)
	return !now.Before(end) || !now.Before(sess.LastActivityAt.Add(idle))
}

// --- internals ---------------------------------------------------------------

type sessionPolicy struct {
	SessionDurations
	// rememberMe: new sessions may be remembered. Same as RememberMe, except
	// when the settings could not be read: a database hiccup must neither
	// end the remembered sessions (RememberMe stays on for them) nor start
	// new ones.
	rememberMe bool
}

func (s *SessionService) policy(ctx context.Context, realmID string) sessionPolicy {
	now := time.Now()
	s.policyMu.Lock()
	c, ok := s.policyCache[realmID]
	s.policyMu.Unlock()
	if ok && now.Sub(c.fetchedAt) < policyCacheTTL {
		return c.policy
	}

	p := s.loadPolicy(ctx, realmID)

	s.policyMu.Lock()
	s.policyCache[realmID] = cachedPolicy{policy: p, fetchedAt: now}
	s.policyMu.Unlock()
	return p
}

func (s *SessionService) loadPolicy(ctx context.Context, realmID string) sessionPolicy {
	settings, err := s.settings.GetByRealmID(ctx, realmID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			d := SessionDurationsOf(nil)
			return sessionPolicy{SessionDurations: d, rememberMe: d.RememberMe}
		}
		s.logger.WarnContext(ctx, "session policy: cannot read instance settings, using defaults",
			"realm_id", realmID, "error", err)
		return sessionPolicy{SessionDurations: SessionDurationsOf(nil), rememberMe: false}
	}
	d := SessionDurationsOf(settings)
	return sessionPolicy{SessionDurations: d, rememberMe: d.RememberMe}
}

func (s *SessionService) lookup(ctx context.Context, tokenHash string) (*domain.Session, bool, error) {
	res, err := s.cache.Get(ctx, tokenHash)
	if err != nil {
		s.logger.WarnContext(ctx, "session cache unavailable, falling back to postgres", "error", err)
	} else {
		if res.Revoked {
			return nil, false, ErrSessionInvalid
		}
		if res.Entry != nil {
			return res.Entry.ToSession(tokenHash), true, nil
		}
	}

	sess, err := s.sessions.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, false, ErrSessionInvalid
		}
		return nil, false, fmt.Errorf("validate session: %w", err)
	}
	return sess, false, nil
}

func (s *SessionService) touch(ctx context.Context, sess *domain.Session, now time.Time) {
	if err := s.sessions.Touch(ctx, sess.ID, now); err != nil {
		s.logger.WarnContext(ctx, "session touch failed", "session_id", sess.ID, "error", err)
		return
	}
	sess.LastActivityAt = now
	if err := s.cache.Refresh(ctx, sess.TokenHash, sessioncache.EntryFromSession(sess), s.ttl(sess)); err != nil {
		s.logger.WarnContext(ctx, "session cache refresh failed", "session_id", sess.ID, "error", err)
	}
}

func (s *SessionService) fillCache(ctx context.Context, sess *domain.Session) {
	if err := s.cache.Fill(ctx, sess.TokenHash, sessioncache.EntryFromSession(sess), s.ttl(sess)); err != nil {
		s.logger.WarnContext(ctx, "session cache fill failed", "session_id", sess.ID, "error", err)
	}
}

func (s *SessionService) expire(ctx context.Context, sess *domain.Session) {
	if err := s.sessions.MarkExpired(ctx, sess.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		s.logger.WarnContext(ctx, "session mark expired failed", "session_id", sess.ID, "error", err)
	}
	if err := s.markRevoked(ctx, sess); err != nil {
		s.logger.WarnContext(ctx, "session cache tombstone failed", "session_id", sess.ID, "error", err)
	}
}

func (s *SessionService) markRevoked(ctx context.Context, sess *domain.Session) error {
	if err := s.cache.MarkRevoked(ctx, sess.TokenHash, s.ttl(sess)); err != nil {
		return fmt.Errorf("session cache tombstone: %w", err)
	}
	return nil
}

func (s *SessionService) ttl(sess *domain.Session) time.Duration {
	return sess.ExpiresAt.Sub(s.now())
}
