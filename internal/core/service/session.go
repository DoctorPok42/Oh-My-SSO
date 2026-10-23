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

	observer LoginObserver // Step 12, optional
}

// LoginObserver is told about every new session, i.e. every completed
// sign-in (Step 12: new device and unusual sign-in detection). It must not
// block: LoginSecurityService does its work in the background.
type LoginObserver interface {
	SessionCreated(ctx context.Context, sess *domain.Session)
}

// WithLoginObserver plugs a LoginObserver into Create.
func WithLoginObserver(o LoginObserver) SessionOption {
	return func(s *SessionService) { s.observer = o }
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
	// DeviceFingerprint (Step 12) is DeviceFingerprint(<id from the
	// sso_device cookie>): the same browser gives the same value, which is
	// how a sign-in from a new device is spotted.
	DeviceFingerprint string
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

	now := s.now()
	sess, err = s.sessions.Create(ctx, repository.CreateSessionParams{
		CreatedAt:         now,
		TokenHash:         HashSessionToken(rawToken),
		RealmID:           in.RealmID,
		UserID:            in.UserID,
		ExpiresAt:         now.Add(policy.maxLifetime),
		IPAddress:         in.IPAddress,
		UserAgent:         in.UserAgent,
		MFAVerified:       in.MFAVerified,
		MFAMethodType:     in.MFAMethodType,
		MFAVerifiedAt:     mfaAt,
		AuthMethod:        authMethod,
		DeviceFingerprint: in.DeviceFingerprint,
	})
	if err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}

	if s.observer != nil {
		s.observer.SessionCreated(ctx, sess)
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
	if limits.IdleTimeout > policy.idleTimeout {
		return fmt.Errorf("%w: idle %s > realm %s", ErrClientSessionLimitTooLong, limits.IdleTimeout, policy.idleTimeout)
	}
	if limits.MaxLifetime > policy.maxLifetime {
		return fmt.Errorf("%w: max %s > realm %s", ErrClientSessionLimitTooLong, limits.MaxLifetime, policy.maxLifetime)
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

	if !now.Before(sess.ExpiresAt) || !now.Before(sess.LastActivityAt.Add(policy.idleTimeout)) {
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
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.LastActivityAt.Add(policy.idleTimeout)) {
		s.expire(ctx, sess)
		return nil, ErrSessionInvalid
	}
	return sess, nil
}

// TouchActive records activity on a session found by its id, for
// back-channel calls that DO prove the user is still using an application:
// a refresh token exchange (Step 10, refresh tokens are bound to the SSO
// session, like Keycloak). Same validity rules as GetActive; the activity
// timestamp moves at most once per touchInterval.
func (s *SessionService) TouchActive(ctx context.Context, sessionID string) (*domain.Session, error) {
	sess, err := s.GetActive(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if now := s.now(); now.Sub(sess.LastActivityAt) >= touchInterval {
		s.touch(ctx, sess, now)
	}
	return sess, nil
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

func (s *SessionService) Logout(ctx context.Context, rawToken string) error {
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
	if err := s.sessions.Revoke(ctx, sess.ID, domain.SessionRevokedUserLogout); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("logout: %w", err)
	}
	if err := s.markRevoked(ctx, sess); err != nil {
		return err
	}
	return s.revokeSessionTokens(ctx, sess.ID)
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

// --- internals ---------------------------------------------------------------

type sessionPolicy struct {
	maxLifetime time.Duration
	idleTimeout time.Duration
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
	p := sessionPolicy{
		maxLifetime: defaultSessionMaxLifetime,
		idleTimeout: defaultSessionIdleTimeout,
	}
	settings, err := s.settings.GetByRealmID(ctx, realmID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			s.logger.WarnContext(ctx, "session policy: cannot read instance settings, using defaults",
				"realm_id", realmID, "error", err)
		}
		return p
	}
	if settings.SessionMaxHours > 0 {
		p.maxLifetime = time.Duration(settings.SessionMaxHours) * time.Hour
	}
	if settings.SessionIdleMinutes > 0 {
		p.idleTimeout = time.Duration(settings.SessionIdleMinutes) * time.Minute
	}
	return p
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
