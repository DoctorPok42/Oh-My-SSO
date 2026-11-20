package service

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // the Pwned Passwords range API is keyed by SHA-1
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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

// DefaultPwnedPasswordsURL is the Have I Been Pwned range API; the 5
// first hex digits of the password's SHA-1 are appended to it.
const DefaultPwnedPasswordsURL = "https://api.pwnedpasswords.com/range/"

var pwnedClient = &http.Client{Timeout: 3 * time.Second}

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
	ErrPasswordCompromised     = errors.New("service: password is too common or appeared in a data breach")
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
	// PwnedPasswordsURL: DefaultPwnedPasswordsURL; tests point it elsewhere,
	// empty turns the check off.
	PwnedPasswordsURL string
}

// NewPasswordPolicyService reads the policy from InstanceSettings. settings
// may be nil: then the defaults apply (12 characters minimum).
func NewPasswordPolicyService(settings repository.InstanceSettingsRepository) *PasswordPolicyService {
	p := &PasswordPolicyService{settings: newSettingsCache(settings, slog.Default()), PwnedPasswordsURL: DefaultPwnedPasswordsURL}
	if settings == nil {
		p.PwnedPasswordsURL = "" // no settings store (unit tests, tools): never call the network
	}
	return p
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
	if p.PwnedPasswordsURL != "" && p.settings.get(ctx, realmID).PasswordBreachCheckEnabled {
		pwned, err := p.pwned(ctx, password)
		if err != nil {
			// Fail open: the local list above already refused the most common ones.
			slog.WarnContext(ctx, "password policy: Have I Been Pwned did not answer, password accepted", "realm_id", realmID, "error", err)
		} else if pwned {
			return fail(ErrPasswordCompromised)
		}
	}
	return nil
}

// pwned asks Have I Been Pwned whether password appeared in a breach. Only
// the 5 first hex digits of its SHA-1 leave the server (k-anonymity), and
// padding hides the size of the answer.
func (p *PasswordPolicyService) pwned(ctx context.Context, password string) (bool, error) {
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(password))) //nolint:gosec // see the import
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.PwnedPasswordsURL+sum[:5], nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Oh-My-SSO") // the API refuses requests without one
	resp, err := pwnedClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned passwords: HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		// "SUFFIX:COUNT"; padding lines have a count of 0.
		suffix, count, _ := strings.Cut(sc.Text(), ":")
		if strings.EqualFold(suffix, sum[5:]) {
			return strings.TrimSpace(count) != "0", nil
		}
	}
	return false, sc.Err()
}
