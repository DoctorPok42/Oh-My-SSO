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

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/sessioncache"
)

var ErrSessionInvalid = errors.New("service: session invalid")
var ErrReauthRequired = errors.New("service: reauthentication required for this app")
var ErrClientSessionLimitTooLong = errors.New("service: app session limit exceeds realm limit")

const (
	// Aligned https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#introduction
	defaultSessionMaxLifetime = 8 * time.Hour
	defaultSessionIdleTimeout = 10 * time.Minute

	touchInterval = time.Minute
	policyCacheTTL = time.Minute
)

type SessionService struct {
	sessions repository.SessionRepository
	settings repository.InstanceSettingsRepository
	cache    sessioncache.Cache
	now      func() time.Time
	logger   *slog.Logger

	policyMu    sync.Mutex
	policyCache map[string]cachedPolicy
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
	cache sessioncache.Cache,
	opts ...SessionOption,
) *SessionService {
	s := &SessionService{
		sessions:    sessions,
		settings:    settings,
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
}

func (s *SessionService) Create(ctx context.Context, in CreateSessionInput) (rawToken string, sess *domain.Session, err error) {
	policy := s.policy(ctx, in.RealmID)

	rawToken = rand.Text()
	authMethod := in.AuthMethod
	if authMethod == "" {
		authMethod = "password"
	}

	sess, err = s.sessions.Create(ctx, repository.CreateSessionParams{
		TokenHash:     HashSessionToken(rawToken),
		RealmID:       in.RealmID,
		UserID:        in.UserID,
		ExpiresAt:     s.now().Add(policy.maxLifetime),
		IPAddress:     in.IPAddress,
		UserAgent:     in.UserAgent,
		MFAVerified:   in.MFAVerified,
		MFAMethodType: in.MFAMethodType,
		AuthMethod:    authMethod,
	})
	if err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
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
	return s.markRevoked(ctx, sess)
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
	return s.markRevoked(ctx, sess)
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
