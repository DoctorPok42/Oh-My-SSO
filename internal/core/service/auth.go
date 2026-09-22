package service

import (
	"context"
	"errors"
	"fmt"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

var (
	ErrInvalidCredentials = errors.New("service: invalid credentials")
	ErrAccountNotActive   = errors.New("service: account not active")
)

type AuthService struct {
	users         repository.UserRepository
	loginAttempts repository.LoginAttemptRepository
}

func NewAuthService(users repository.UserRepository, loginAttempts repository.LoginAttemptRepository) *AuthService {
	return &AuthService{users: users, loginAttempts: loginAttempts}
}

type AuthenticateLocalParams struct {
	RealmID    string
	Identifier string // username or email
	Password   string
	IPAddress  string
	UserAgent  string
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
