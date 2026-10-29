package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Aliases of the core errors: same variables, so errors.Is matches both names.
var (
	ErrInvalidCredentials = core.ErrInvalidCredentials
	ErrAccountNotActive   = core.ErrAccountNotActive
	ErrTimeoutActive      = core.ErrTimeoutActive
)

type AuthService struct {
	users         repository.UserRepository
	loginAttempts repository.LoginAttemptRepository
	timeouts      TimeoutChecker
	lockout       *LockoutService
	logger        *slog.Logger
}

type AuthOption func(*AuthService)

// WithTimeoutChecker plugs the Timeout check into AuthenticateLocal.
// Defaults to NoActiveTimeouts.
func WithTimeoutChecker(tc TimeoutChecker) AuthOption {
	return func(s *AuthService) {
		if tc != nil {
			s.timeouts = tc
		}
	}
}

func WithLockout(l *LockoutService) AuthOption {
	return func(s *AuthService) { s.lockout = l }
}

func NewAuthService(users repository.UserRepository, loginAttempts repository.LoginAttemptRepository, opts ...AuthOption) *AuthService {
	s := &AuthService{users: users, loginAttempts: loginAttempts, timeouts: NoActiveTimeouts{}, logger: slog.Default()}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type AuthenticateLocalParams struct {
	RealmID    string
	Identifier string // username or email
	Password   string
	IPAddress  string
	UserAgent  string
	ClientRef  string // optional: ClientApp.ID the login is for (timeout check)
}

func (s *AuthService) AuthenticateLocal(ctx context.Context, p AuthenticateLocalParams) (*domain.User, error) {
	user, err := s.findUserByIdentifier(ctx, p.RealmID, p.Identifier)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("authenticate local: lookup user: %w", err)
	}
	subj := LockoutSubject{RealmID: p.RealmID, User: user, Identifier: p.Identifier, IPAddress: p.IPAddress, UserAgent: p.UserAgent}

	if s.lockout != nil {
		until, err := s.lockout.Check(ctx, subj)
		if err != nil {
			return nil, fmt.Errorf("authenticate local: %w", err)
		}
		if !until.IsZero() {
			reason := domain.LoginFailureAccountLocked
			if user == nil {
				reason = domain.LoginFailureUnknownAccount
			}
			s.recordAttempt(ctx, p, user, domain.LoginAttemptFailure, reason)
			return nil, &AccountLockedError{Until: until}
		}
	}

	if user == nil || user.PasswordHash == "" {
		// Same work as a real check, so the response time does not tell
		// whether the account exists (timing attack).
		burnPasswordCheck(p.Password)
		reason := domain.LoginFailureInvalidCredentials
		if user == nil {
			reason = domain.LoginFailureUnknownAccount
		}
		s.recordAttempt(ctx, p, user, domain.LoginAttemptFailure, reason)
		s.recordFailure(ctx, subj)
		return nil, ErrInvalidCredentials
	}

	ok, err := verifyPassword(p.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("authenticate local: verify password: %w", err)
	}
	if !ok {
		s.recordAttempt(ctx, p, user, domain.LoginAttemptFailure, domain.LoginFailureInvalidCredentials)
		s.recordFailure(ctx, subj)
		return nil, ErrInvalidCredentials
	}

	// The password is right: whatever happens next, earlier failures were
	// not an attack that succeeded, forget them.
	if s.lockout != nil {
		if err := s.lockout.RecordSuccess(ctx, user); err != nil {
			s.logger.WarnContext(ctx, "lockout: cannot clear failed sign-ins", "user_id", user.ID, "error", err)
		}
	}

	if user.Status != domain.UserActive {
		s.recordAttempt(ctx, p, user, domain.LoginAttemptFailure, domain.LoginFailureAccountLocked)
		return nil, ErrAccountNotActive
	}

	// Checked only once the password is proven correct, so a blocked state
	// is never revealed to someone who doesn't know the password. The error
	// is a *core.TimeoutError (errors.Is ErrTimeoutActive).
	if err := checkTimeout(ctx, s.timeouts, user.ID, p.ClientRef); err != nil {
		if !errors.Is(err, ErrTimeoutActive) {
			return nil, fmt.Errorf("authenticate local: check timeout: %w", err)
		}
		s.recordAttempt(ctx, p, user, domain.LoginAttemptFailure, domain.LoginFailureTimeoutActive)
		return nil, err
	}

	s.recordAttempt(ctx, p, user, domain.LoginAttemptSuccess, "")
	return user, nil
}

// recordFailure counts a wrong password for the lockout. An error here must
// not turn a wrong password into a server error: it is logged.
func (s *AuthService) recordFailure(ctx context.Context, subj LockoutSubject) {
	if s.lockout == nil {
		return
	}
	if _, err := s.lockout.RecordFailure(ctx, subj); err != nil {
		s.logger.WarnContext(ctx, "lockout: cannot count failed sign-in", "realm_id", subj.RealmID, "error", err)
	}
}

// dummyPasswordHash is checked when there is no real hash to check, so that
// "no such account" costs as much time as "wrong password".
var dummyPasswordHash = sync.OnceValue(func() string {
	h, err := HashPassword(rand.Text())
	if err != nil {
		panic(err) // crypto/rand cannot fail since Go 1.24
	}
	return h
})

func burnPasswordCheck(password string) {
	_, _ = verifyPassword(password, dummyPasswordHash())
}

func (s *AuthService) findUserByIdentifier(ctx context.Context, realmID, identifier string) (*domain.User, error) {
	u, err := s.users.GetByRealmAndUsername(ctx, realmID, identifier)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}

	u, err = s.users.GetByRealmAndEmail(ctx, realmID, identifier)
	if err == nil {
		return u, nil
	}
	if errors.Is(err, repository.ErrNotFound) {
		return nil, repository.ErrNotFound
	}
	return nil, err
}

func (s *AuthService) recordAttempt(ctx context.Context, p AuthenticateLocalParams, user *domain.User, status domain.LoginAttemptStatus, reason domain.LoginAttemptFailureReason) {
	userID := ""
	if user != nil {
		userID = user.ID
	}
	_, _ = s.loginAttempts.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID:       p.RealmID,
		UserID:        userID,
		Identifier:    p.Identifier,
		IPAddress:     p.IPAddress,
		UserAgent:     p.UserAgent,
		Status:        status,
		FailureReason: reason,
	})
}
