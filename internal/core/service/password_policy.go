package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


const (
	// MaxPasswordLength in characters. NIST asks for at least 64.
	MaxPasswordLength = 256
	// minPasswordLengthFloor: a realm cannot ask for less (NIST minimum).
	minPasswordLengthFloor = 8
)

var (
	ErrPasswordTooShort        = errors.New("service: password is too short")
	ErrPasswordTooLong         = errors.New("service: password is too long")
	ErrPasswordMatchesIdentity = errors.New("service: password must not be the username or e-mail")
)

// PasswordPolicyError tells which rule failed, with the limits to show to
// the user. errors.Is works with the three errors above.
type PasswordPolicyError struct {
	Err       error
	MinLength int
	MaxLength int
}

func (e *PasswordPolicyError) Error() string {
	return fmt.Sprintf("%s (min %d, max %d characters)", e.Err, e.MinLength, e.MaxLength)
}
func (e *PasswordPolicyError) Unwrap() error { return e.Err }

// PasswordPolicyService checks new passwords against the realm's policy.
type PasswordPolicyService struct {
	settings *settingsCache
}

// NewPasswordPolicyService reads the policy from InstanceSettings. settings
// may be nil: then the defaults apply (12 characters minimum).
func NewPasswordPolicyService(settings repository.InstanceSettingsRepository) *PasswordPolicyService {
	return &PasswordPolicyService{settings: newSettingsCache(settings, slog.Default())}
}

// MinLength returns the minimum length of a new password in this realm.
func (p *PasswordPolicyService) MinLength(ctx context.Context, realmID string) int {
	n := p.settings.get(ctx, realmID).MinPasswordLength
	if n <= 0 {
		n = defaultMinPasswordLength
	}
	if n < minPasswordLengthFloor {
		n = minPasswordLengthFloor
	}
	if n > MaxPasswordLength {
		n = MaxPasswordLength
	}
	return n
}

// Validate returns nil if password may become the password of user (may be
// nil when the account does not exist yet) in realm realmID, or a
// *PasswordPolicyError.
func (p *PasswordPolicyService) Validate(ctx context.Context, realmID, password string, user *domain.User) error {
	minLen := p.MinLength(ctx, realmID)
	fail := func(err error) error {
		return &PasswordPolicyError{Err: err, MinLength: minLen, MaxLength: MaxPasswordLength}
	}

	n := utf8.RuneCountInString(password)
	if n < minLen {
		return fail(ErrPasswordTooShort)
	}
	if n > MaxPasswordLength {
		return fail(ErrPasswordTooLong)
	}
	if user != nil {
		for _, own := range []string{user.Username, user.Email} {
			if own != "" && strings.EqualFold(strings.TrimSpace(password), own) {
				return fail(ErrPasswordMatchesIdentity)
			}
		}
	}
	return nil
}
