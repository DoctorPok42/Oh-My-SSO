package service

import (
	"context"
	"errors"
	"fmt"

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

func NewAuthService(users repository.UserRepository, loginAttempts repository.LoginAttemptRepository, opts ...AuthOption) *AuthService {
	s := &AuthService{users: users, loginAttempts: loginAttempts, timeouts: NoActiveTimeouts{}}
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

	if user == nil {
		s.recordAttempt(ctx, p, domain.LoginAttemptFailure, domain.LoginFailureUnknownAccount)
		return nil, ErrInvalidCredentials
	}

	if user.PasswordHash == "" {
		s.recordAttempt(ctx, p, domain.LoginAttemptFailure, domain.LoginFailureInvalidCredentials)
		return nil, ErrInvalidCredentials
	}

	ok, err := verifyPassword(p.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("authenticate local: verify password: %w", err)
	}
	if !ok {
		s.recordAttempt(ctx, p, domain.LoginAttemptFailure, domain.LoginFailureInvalidCredentials)
		return nil, ErrInvalidCredentials
	}

	if user.Status != domain.UserActive {
		s.recordAttempt(ctx, p, domain.LoginAttemptFailure, domain.LoginFailureAccountLocked)
		return nil, ErrAccountNotActive
	}

	// Checked only once the password is proven correct, so a blocked state
	// is never revealed to someone who doesn't know the password.
	blocked, err := s.timeouts.HasActiveTimeout(ctx, user.ID, p.ClientRef)
	if err != nil {
		return nil, fmt.Errorf("authenticate local: check timeout: %w", err)
	}
	if blocked {
		s.recordAttempt(ctx, p, domain.LoginAttemptFailure, domain.LoginFailureTimeoutActive)
		return nil, ErrTimeoutActive
	}

	s.recordAttempt(ctx, p, domain.LoginAttemptSuccess, "")
	return user, nil
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

func (s *AuthService) recordAttempt(ctx context.Context, p AuthenticateLocalParams, status domain.LoginAttemptStatus, reason domain.LoginAttemptFailureReason) {
	_, _ = s.loginAttempts.Create(ctx, repository.CreateLoginAttemptParams{
		Identifier:    p.Identifier,
		IPAddress:     p.IPAddress,
		UserAgent:     p.UserAgent,
		Status:        status,
		FailureReason: reason,
	})
}
