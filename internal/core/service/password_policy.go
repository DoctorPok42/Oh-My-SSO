package service

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// commonPasswordsTxt: the NCSC list of the 100,000 passwords most seen in
// Have I Been Pwned (via SecLists, MIT), lower-cased, minus those shorter
// than 8 characters (the length floor refuses them already).
//
//go:embed common_passwords.txt
var commonPasswordsTxt string

var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 50000)
	for _, line := range strings.Split(commonPasswordsTxt, "\n") {
		if line = strings.TrimSuffix(line, "\r"); line != "" { // CRLF in a Windows checkout
			set[strings.ToLower(line)] = struct{}{}
		}
	}
	return set
})

// PasswordBreachChecker tells whether a password appeared in a data breach.
// It is a port: the adapter is internal/pwnedpasswords (Have I Been Pwned).
type PasswordBreachChecker interface {
	Pwned(ctx context.Context, password string) (bool, error)
}

const (
	// MaxPasswordLength in characters. NIST asks for at least 64.
	MaxPasswordLength = 256
	// minPasswordLengthFloor: a realm cannot ask for less (NIST minimum).
	minPasswordLengthFloor = 8
	// MaxPasswordHistoryCount: each remembered password costs one Argon2id
	// check (64 MiB) when a new password is chosen.
	MaxPasswordHistoryCount = 10
	// DefaultPasswordHistoryCount: a new realm refuses the last 5 passwords.
	DefaultPasswordHistoryCount = 5
	// MaxPasswordExpiryDays: ten years.
	MaxPasswordExpiryDays = 3650
)

var (
	ErrPasswordTooShort        = errors.New("service: password is too short")
	ErrPasswordTooLong         = errors.New("service: password is too long")
	ErrPasswordMatchesIdentity = errors.New("service: password must not be the username or e-mail")
	ErrPasswordCompromised     = errors.New("service: password is too common or appeared in a data breach")
	ErrPasswordReused          = errors.New("service: password was used recently")
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
	// Breach: nil turns the breach check off whatever the realm says (unit
	// tests, tools); the server wires the Have I Been Pwned adapter.
	Breach PasswordBreachChecker
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
	if _, common := commonPasswords()[strings.ToLower(password)]; common {
		return fail(ErrPasswordCompromised)
	}
	st := p.settings.get(ctx, realmID)
	if user != nil {
		for _, hash := range recentPasswords(user, st.PasswordHistoryCount) {
			same, err := verifyPassword(ctx, password, hash)
			if err != nil {
				return fmt.Errorf("password policy: compare with a previous password: %w", err)
			}
			if same {
				return fail(ErrPasswordReused)
			}
		}
	}
	if p.Breach != nil && st.PasswordBreachCheckEnabled {
		pwned, err := p.Breach.Pwned(ctx, password)
		if err != nil {
			// Fail open: the local list above already refused the most common ones.
			slog.WarnContext(ctx, "password policy: Have I Been Pwned did not answer, password accepted", "realm_id", realmID, "error", err)
		} else if pwned {
			return fail(ErrPasswordCompromised)
		}
	}
	return nil
}

// recentPasswords: the hashes of the user's last n passwords, the current
// one first.
func recentPasswords(user *domain.User, n int) []string {
	n = min(n, MaxPasswordHistoryCount)
	if n <= 0 || user.PasswordHash == "" {
		return nil
	}
	return append([]string{user.PasswordHash}, user.PasswordHistory[:min(n-1, len(user.PasswordHistory))]...)
}

// PasswordChange returns what to write with the new hash of user's password:
// the change time and the history the realm keeps (the current password
// becomes the newest previous one). Only as many hashes as the realm's
// history needs are kept: none when it is off.
func (p *PasswordPolicyService) PasswordChange(ctx context.Context, user *domain.User, hash string, now time.Time) repository.UpdateUserParams {
	n := min(p.settings.get(ctx, user.RealmID).PasswordHistoryCount, MaxPasswordHistoryCount)
	history := []string{} // empty, not nil: clears what an earlier, longer setting kept
	if n > 1 {
		history = recentPasswords(user, n-1)
	}
	return repository.UpdateUserParams{PasswordHash: &hash, PasswordChangedAt: &now, PasswordHistory: &history}
}

// PasswordExpired reports whether user's password is older than the realm
// allows. A password without a known change time never expires.
func (p *PasswordPolicyService) PasswordExpired(ctx context.Context, user *domain.User, now time.Time) bool {
	days := p.settings.get(ctx, user.RealmID).PasswordExpiryDays
	if days <= 0 || user.PasswordChangedAt.IsZero() {
		return false
	}
	return now.After(user.PasswordChangedAt.AddDate(0, 0, days))
}
