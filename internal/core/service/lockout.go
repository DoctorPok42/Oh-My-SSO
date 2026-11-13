package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/audit"
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
	// DeviceFingerprint: the browser's sso_device cookie, hashed as on the
	// sessions (DeviceFingerprint); "" without one. A device the user already
	// signed in from is not held by a lock that others caused (see Check).
	DeviceFingerprint string
}

// SignInHistory lists the sessions of a user, the devices they signed in
// from (repository.SessionRepository implements it).
type SignInHistory interface {
	ListRecentByUser(ctx context.Context, userID string, since time.Time, limit int) ([]*domain.Session, error)
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
	history  SignInHistory
	settings *settingsCache
	notifier Notifier
	audit    repository.AuditLogRepository
	now      func() time.Time
	logger   *slog.Logger
}

// LockoutDeps groups the dependencies of NewLockoutService.
type LockoutDeps struct {
	Users repository.UserRepository
	// Unknown: state of identifiers without an account, and of the known
	// devices of an account.
	Unknown  lockoutstore.Store
	History  SignInHistory                         // optional: no known device without it
	Settings repository.InstanceSettingsRepository // nil: defaults (5 tries, 15 min)
	Notifier Notifier                              // optional: "account locked" e-mail
	Audit    repository.AuditLogRepository         // optional: "user.locked" entry
	Now      func() time.Time                      // optional (tests)
	Logger   *slog.Logger                          // optional
}

func NewLockoutService(d LockoutDeps) *LockoutService {
	s := &LockoutService{
		users:    d.Users,
		unknown:  d.Unknown,
		history:  d.History,
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
//
// A locked account is not locked for a device the user already signed in
// from (a session from it in the last 90 days, the history of the new
// device alerts), unless that device made the failures itself: its own
// counter, kept apart, is locked then. Someone who only knows the
// identifier of an account, an administrator's say, can lock it everywhere
// else but not on its owner's devices (audit B-14). The lock, its e-mail and
// the console stay as they were.
func (s *LockoutService) Check(ctx context.Context, subj LockoutSubject) (time.Time, error) {
	if s.Policy(ctx, subj.RealmID).Threshold <= 0 {
		return time.Time{}, nil
	}
	st, err := s.backend(subj).load(ctx, subj.User)
	if err != nil {
		return time.Time{}, fmt.Errorf("lockout check: %w", err)
	}
	now := s.now()
	if !st.LockedAt(now) {
		return time.Time{}, nil
	}
	if s.knownDeviceGoesOn(ctx, subj, now) {
		s.logger.InfoContext(ctx, "account locked: sign-in allowed from a device the user signed in from before",
			"realm_id", subj.RealmID, "user_id", subj.User.ID, "locked_until", st.LockedUntil)
		return time.Time{}, nil
	}
	return st.LockedUntil, nil
}

// knownDeviceGoesOn: subj comes from a device of the user's that did not
// lock itself. Any error keeps the lock (logged).
func (s *LockoutService) knownDeviceGoesOn(ctx context.Context, subj LockoutSubject, now time.Time) bool {
	if subj.User == nil || subj.DeviceFingerprint == "" || s.history == nil {
		return false
	}
	dev, err := s.device(subj).load(ctx, nil)
	if err != nil {
		s.logger.WarnContext(ctx, "lockout: cannot read the device's counter, the lock applies", "user_id", subj.User.ID, "error", err)
		return false
	}
	if dev.LockedAt(now) {
		return false
	}
	known, err := s.knownDevice(ctx, subj, now)
	if err != nil {
		s.logger.WarnContext(ctx, "lockout: cannot read the sign-in history, the lock applies", "user_id", subj.User.ID, "error", err)
		return false
	}
	return known
}

// knownDevice: the user has a session from subj's device in the history that
// the new device alerts use (LoginSecurityService): a device that would not
// be "new" there is known here. A session exists only after a complete
// sign-in (password and second factor), and the cookie is a random value
// set by this server, HttpOnly: having it means having used that browser.
func (s *LockoutService) knownDevice(ctx context.Context, subj LockoutSubject, now time.Time) (bool, error) {
	if subj.User == nil || subj.DeviceFingerprint == "" || s.history == nil {
		return false, nil
	}
	sessions, err := s.history.ListRecentByUser(ctx, subj.User.ID, now.Add(-loginHistoryWindow), loginHistoryLimit)
	if err != nil {
		return false, err
	}
	for _, sess := range sessions {
		if sess.DeviceFingerprint == subj.DeviceFingerprint {
			return true, nil
		}
	}
	return false, nil
}

// RecordFailure counts a wrong password. When it starts a lock on a real
// account, the AuditLog entry and the e-mail are taken care of here.
//
// Every failure counts towards the account, as always. A failure from a
// known device also counts towards that device's own counter: past the
// threshold, the device no longer goes past a lock of the account (Check).
func (s *LockoutService) RecordFailure(ctx context.Context, subj LockoutSubject) (FailureResult, error) {
	policy := s.Policy(ctx, subj.RealmID)
	if policy.Threshold <= 0 {
		return FailureResult{}, nil
	}
	var res FailureResult
	err := s.update(ctx, s.backend(subj), subj.User, func(st domain.LockoutState, now time.Time) domain.LockoutState {
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
	s.recordDeviceFailure(ctx, subj, policy)
	return res, nil
}

// recordDeviceFailure counts a failure on the device's own counter, when the
// device is known (an unknown one never goes past a lock: no counter to
// keep). Best effort: an error is logged, the device then simply keeps
// going past a lock a little longer.
func (s *LockoutService) recordDeviceFailure(ctx context.Context, subj LockoutSubject, policy LockoutPolicy) {
	known, err := s.knownDevice(ctx, subj, s.now())
	if err != nil {
		s.logger.WarnContext(ctx, "lockout: cannot read the sign-in history", "user_id", subj.User.ID, "error", err)
		return
	}
	if !known {
		return
	}
	var res FailureResult
	err = s.update(ctx, s.device(subj), nil, func(st domain.LockoutState, now time.Time) domain.LockoutState {
		next, r := applyFailure(st, now, policy)
		res = r
		return next
	})
	if err != nil {
		s.logger.WarnContext(ctx, "lockout: cannot count the failure of a known device", "user_id", subj.User.ID, "error", err)
		return
	}
	if res.JustLocked {
		s.logger.WarnContext(ctx, "known device locked after failed sign-ins: it no longer goes past a lock of the account",
			"realm_id", subj.RealmID, "user_id", subj.User.ID, "until", res.LockedUntil, "failed_attempts", res.FailedAttempts)
	}
}

// RecordSuccess forgets the failures of a user after a correct password: the
// device's own, and the account's. The account's lock stays when there is
// one: the sign-in then came from a known device (Check), and the others
// stay locked out.
func (s *LockoutService) RecordSuccess(ctx context.Context, subj LockoutSubject) error {
	user := subj.User
	if user == nil {
		return nil
	}
	if subj.DeviceFingerprint != "" && s.history != nil {
		// Only known devices have a counter: a read, and a write when it
		// holds failures. The password was right on this device: its
		// failures were its owner's, its own lock goes too.
		forgetAll := func(domain.LockoutState, time.Time) domain.LockoutState { return domain.LockoutState{} }
		if err := s.update(ctx, s.device(subj), nil, forgetAll); err != nil {
			s.logger.WarnContext(ctx, "lockout: cannot clear the failures of the device", "user_id", user.ID, "error", err)
		}
	}
	if user.Lockout.IsZero() {
		return nil // nothing to clear: no write on the usual login
	}
	if err := s.update(ctx, s.backend(subj), user, forgetFailures); err != nil {
		return fmt.Errorf("lockout success: %w", err)
	}
	return nil
}

// forgetFailures: the state after a correct password. A lock in force stays
// (see RecordSuccess); otherwise everything is forgotten.
func forgetFailures(st domain.LockoutState, now time.Time) domain.LockoutState {
	if st.LockedAt(now) {
		return st
	}
	return domain.LockoutState{}
}

// Unlock clears the counters and any lock of a user (admin action, password
// reset, successful login).
func (s *LockoutService) Unlock(ctx context.Context, user *domain.User) error {
	subj := LockoutSubject{RealmID: user.RealmID, User: user}
	err := s.update(ctx, s.backend(subj), user, func(domain.LockoutState, time.Time) domain.LockoutState {
		return domain.LockoutState{}
	})
	if err != nil {
		return fmt.Errorf("lockout unlock: %w", err)
	}
	return nil
}

// update applies change to the state of b with compare-and-swap, retrying
// when a concurrent request changed it in between. user, when not nil, is
// the account just read (its state saves a query on the first round).
func (s *LockoutService) update(ctx context.Context, b lockoutBackend, user *domain.User, change func(domain.LockoutState, time.Time) domain.LockoutState) error {
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
			ActorType:    domain.AuditActorSystem, // the lockout policy, not the user
			TargetUserID: u.ID,
			Action:       audit.UserLocked,
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

// device is the own counter of subj's device for subj's account, kept with
// the identifiers without an account (Valkey, forgotten 48 h after the last
// change). Call it only with a user and a device.
func (s *LockoutService) device(subj LockoutSubject) lockoutBackend {
	return &unknownLockout{store: s.unknown, key: DeviceLockoutKey(subj.RealmID, subj.User.ID, subj.DeviceFingerprint)}
}

// DeviceLockoutKey is the key of the counter of a device for an account:
// apart from the identifiers' (realm:<64 hex>) by its "device:" part.
func DeviceLockoutKey(realmID, userID, deviceFingerprint string) string {
	return realmID + ":device:" + userID + ":" + deviceFingerprint
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
// account: realm + SHA-256 of the identifier (normalized like the accounts'),
// so that "Alice" and "alice " share one counter and Valkey never stores what
// an attacker typed.
func UnknownIdentifierKey(realmID, identifier string) string {
	sum := sha256.Sum256([]byte(domain.NormalizeIdentifier(identifier)))
	return realmID + ":" + hex.EncodeToString(sum[:])
}
