package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/lockoutstore"
)


var ErrAccountLocked = core.ErrAccountLocked // alias: same variable as core

// AccountLockedError is ErrAccountLocked with the time the lock ends (for
// the Retry-After header).
type AccountLockedError struct {
	Until time.Time
}

func (e *AccountLockedError) Error() string {
	return fmt.Sprintf("%s (until %s)", ErrAccountLocked, e.Until.UTC().Format(time.RFC3339))
}
func (e *AccountLockedError) Unwrap() error { return ErrAccountLocked }

const (
	maxLockoutDuration = 24 * time.Hour
	// lockoutMemory: a new lock less than this after the end of the previous
	// one doubles. Unknown identifiers are forgotten after lockoutMemory +
	// maxLockoutDuration.
	lockoutMemory   = 24 * time.Hour
	maxCASAttempts  = 8
	unknownStateTTL = lockoutMemory + maxLockoutDuration
)

// LockoutPolicy is the lockout part of InstanceSettings.
type LockoutPolicy struct {
	Threshold int           // wrong passwords in a row before a lock; <= 0 disables lockout
	Duration  time.Duration // first lock, and the observation window
}

// LockoutSubject is who a login attempt is for: a real user, or an
// identifier that matches no account.
type LockoutSubject struct {
	RealmID    string
	User       *domain.User // nil: no such account
	Identifier string       // what was typed (used only when User is nil)
	IPAddress  string
	UserAgent  string
}

// FailureResult says what a wrong password did.
type FailureResult struct {
	JustLocked     bool      // this failure started a lock
	LockedUntil    time.Time // when that lock ends
	FailedAttempts int       // wrong passwords that led to it
}

// LockoutService keeps the counters and decides on locks.
type LockoutService struct {
	users    repository.UserRepository
	unknown  lockoutstore.Store
	settings *settingsCache
	notifier Notifier
	audit    repository.AuditLogRepository
	now      func() time.Time
	logger   *slog.Logger
}

// LockoutDeps groups the dependencies of NewLockoutService.
type LockoutDeps struct {
	Users    repository.UserRepository
	Unknown  lockoutstore.Store                    // state of identifiers without an account
	Settings repository.InstanceSettingsRepository // nil: defaults (5 tries, 15 min)
	Notifier Notifier                              // optional: "account locked" e-mail
	Audit    repository.AuditLogRepository         // optional: "account_locked" entry
	Now      func() time.Time                      // optional (tests)
	Logger   *slog.Logger                          // optional
}

func NewLockoutService(d LockoutDeps) *LockoutService {
	s := &LockoutService{
		users:    d.Users,
		unknown:  d.Unknown,
		notifier: d.Notifier,
		audit:    d.Audit,
		now:      d.Now,
		logger:   d.Logger,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.notifier == nil {
		s.notifier = NopNotifier{}
	}
	if s.unknown == nil {
		s.unknown = lockoutstore.NewMemory(s.now)
	}
	s.settings = newSettingsCache(d.Settings, s.logger)
	return s
}

// Policy returns the realm's lockout policy.
func (s *LockoutService) Policy(ctx context.Context, realmID string) LockoutPolicy {
	st := s.settings.get(ctx, realmID)
	d := time.Duration(st.LockoutDurationMinutes) * time.Minute
	if d <= 0 {
		d = defaultLockoutDurationMinutes * time.Minute
	}
	return LockoutPolicy{Threshold: st.LockoutThreshold, Duration: d}
}

// Check returns when the current lock of subj ends, or the zero time when
// sign-in is allowed.
func (s *LockoutService) Check(ctx context.Context, subj LockoutSubject) (time.Time, error) {
	if s.Policy(ctx, subj.RealmID).Threshold <= 0 {
		return time.Time{}, nil
	}
	st, err := s.backend(subj).load(ctx, subj.User)
	if err != nil {
		return time.Time{}, fmt.Errorf("lockout check: %w", err)
	}
	if st.LockedAt(s.now()) {
		return st.LockedUntil, nil
	}
	return time.Time{}, nil
}

// RecordFailure counts a wrong password. When it starts a lock on a real
// account, the AuditLog entry and the e-mail are taken care of here.
func (s *LockoutService) RecordFailure(ctx context.Context, subj LockoutSubject) (FailureResult, error) {
	policy := s.Policy(ctx, subj.RealmID)
	if policy.Threshold <= 0 {
		return FailureResult{}, nil
	}
	var res FailureResult
	err := s.update(ctx, subj, func(st domain.LockoutState, now time.Time) domain.LockoutState {
		next, r := applyFailure(st, now, policy)
		res = r
		return next
	})
	if err != nil {
		return FailureResult{}, fmt.Errorf("lockout record failure: %w", err)
	}
	if res.JustLocked && subj.User != nil {
		s.onLocked(ctx, subj, res)
	}
	return res, nil
}

// RecordSuccess forgets the failures of a user after a correct password.
func (s *LockoutService) RecordSuccess(ctx context.Context, user *domain.User) error {
	if user == nil || user.Lockout.IsZero() {
		return nil // nothing to clear: no write on the usual login
	}
	return s.Unlock(ctx, user)
}

// Unlock clears the counters and any lock of a user (admin action, password
// reset, successful login).
func (s *LockoutService) Unlock(ctx context.Context, user *domain.User) error {
	subj := LockoutSubject{RealmID: user.RealmID, User: user}
	err := s.update(ctx, subj, func(domain.LockoutState, time.Time) domain.LockoutState {
		return domain.LockoutState{}
	})
	if err != nil {
		return fmt.Errorf("lockout unlock: %w", err)
	}
	return nil
}

// update applies change with compare-and-swap, retrying when a concurrent
// request changed the state in between.
func (s *LockoutService) update(ctx context.Context, subj LockoutSubject, change func(domain.LockoutState, time.Time) domain.LockoutState) error {
	b := s.backend(subj)
	user := subj.User
	for i := 0; i < maxCASAttempts; i++ {
		st, err := b.load(ctx, user)
		if err != nil {
			return err
		}
		next := change(st, s.now())
		if next == st {
			return nil
		}
		ok, err := b.cas(ctx, st, next)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		user = nil // reload from storage on the next round
	}
	return errors.New("too many concurrent updates")
}

func (s *LockoutService) onLocked(ctx context.Context, subj LockoutSubject, res FailureResult) {
	u := subj.User
	s.logger.WarnContext(ctx, "account locked after failed sign-ins",
		"realm_id", u.RealmID, "user_id", u.ID, "until", res.LockedUntil, "failed_attempts", res.FailedAttempts)
	if s.audit != nil {
		_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
			RealmID:      u.RealmID,
			UserID:       u.ID,
			Action:       "account_locked",
			ResourceType: "User",
			ResourceID:   u.ID,
			IPAddress:    subj.IPAddress,
			UserAgent:    subj.UserAgent,
			Level:        domain.AuditLogWarning,
			Status:       domain.AuditLogSuccess,
			Details: map[string]interface{}{
				"locked_until":    res.LockedUntil.UTC().Format(time.RFC3339),
				"failed_attempts": res.FailedAttempts,
			},
		})
	}
	s.notifier.Notify(ctx, domain.NotificationEvent{
		Kind:           domain.NotificationAccountLocked,
		RealmID:        u.RealmID,
		UserID:         u.ID,
		OccurredAt:     s.now(),
		IPAddress:      subj.IPAddress,
		UserAgent:      subj.UserAgent,
		ExpiresAt:      res.LockedUntil,
		FailedAttempts: res.FailedAttempts,
	})
}


// applyFailure returns the state after one more wrong password at now.
func applyFailure(st domain.LockoutState, now time.Time, p LockoutPolicy) (domain.LockoutState, FailureResult) {
	if st.LockedAt(now) {
		// Should not happen (the password is not checked while locked), but
		// a request that raced with the lock must not extend it.
		return st, FailureResult{}
	}
	next := st
	if next.LastFailedAt.IsZero() || now.Sub(next.LastFailedAt) > p.Duration {
		next.FailedCount = 0 // the previous failures are too old to count
	}
	next.FailedCount++
	next.LastFailedAt = now
	if next.FailedCount < p.Threshold {
		return next, FailureResult{}
	}

	// Lock. LockedUntil still holds the end of the previous lock (if any):
	// a lock coming back soon after it doubles.
	if next.LockedUntil.IsZero() || now.Sub(next.LockedUntil) > lockoutMemory {
		next.LockCount = 0
	}
	next.LockCount++
	next.LastLockedAt = now
	next.LockedUntil = now.Add(lockDuration(p.Duration, next.LockCount))
	res := FailureResult{JustLocked: true, LockedUntil: next.LockedUntil, FailedAttempts: next.FailedCount}
	next.FailedCount = 0
	return next, res
}

// lockDuration of the n-th lock in a row: base, 2×base, 4×base... ≤ 24 h.
func lockDuration(base time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n; i++ {
		d *= 2
		if d >= maxLockoutDuration {
			return maxLockoutDuration
		}
	}
	if d > maxLockoutDuration {
		return maxLockoutDuration
	}
	return d
}


type lockoutBackend interface {
	// load returns the current state. hint, when not nil, is a user just
	// read from the database (saves a query on the first round).
	load(ctx context.Context, hint *domain.User) (domain.LockoutState, error)
	cas(ctx context.Context, old, next domain.LockoutState) (bool, error)
}

func (s *LockoutService) backend(subj LockoutSubject) lockoutBackend {
	if subj.User != nil {
		return &userLockout{users: s.users, id: subj.User.ID}
	}
	return &unknownLockout{store: s.unknown, key: UnknownIdentifierKey(subj.RealmID, subj.Identifier)}
}

type userLockout struct {
	users repository.UserRepository
	id    string
}

func (b *userLockout) load(ctx context.Context, hint *domain.User) (domain.LockoutState, error) {
	if hint != nil {
		return hint.Lockout, nil
	}
	u, err := b.users.GetByID(ctx, b.id)
	if err != nil {
		return domain.LockoutState{}, err
	}
	return u.Lockout, nil
}

func (b *userLockout) cas(ctx context.Context, old, next domain.LockoutState) (bool, error) {
	return b.users.CompareAndSwapLockout(ctx, b.id, old, next)
}

type unknownLockout struct {
	store lockoutstore.Store
	key   string
}

func (b *unknownLockout) load(ctx context.Context, _ *domain.User) (domain.LockoutState, error) {
	return b.store.Get(ctx, b.key)
}

func (b *unknownLockout) cas(ctx context.Context, old, next domain.LockoutState) (bool, error) {
	return b.store.CompareAndSwap(ctx, b.key, old, next, unknownStateTTL)
}

// UnknownIdentifierKey is the lockout key of an identifier without an
// account: realm + SHA-256 of the identifier (trimmed, lower case), so that
// "Alice" and "alice " share one counter and Valkey never stores what an
// attacker typed.
func UnknownIdentifierKey(realmID, identifier string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(identifier))))
	return realmID + ":" + hex.EncodeToString(sum[:])
}
