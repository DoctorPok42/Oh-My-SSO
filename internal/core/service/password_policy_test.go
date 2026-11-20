package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

func TestPasswordPolicy(t *testing.T) {
	ctx := context.Background()
	user := &domain.User{Username: "Erin", Email: "erin@example.test"}

	t.Run("defaults: 12 characters", func(t *testing.T) {
		p := service.NewPasswordPolicyService(nil)
		require.Equal(t, 12, p.MinLength(ctx, "r"))
		require.ErrorIs(t, p.Validate(ctx, "r", "elevenchars", user), service.ErrPasswordTooShort)
		require.NoError(t, p.Validate(ctx, "r", "twelve chars", user))
	})

	t.Run("length is counted in characters, not bytes", func(t *testing.T) {
		p := service.NewPasswordPolicyService(nil)
		// 11 characters, 18 bytes in UTF-8: still too short.
		require.ErrorIs(t, p.Validate(ctx, "r", "étéétéétéét", user), service.ErrPasswordTooShort)
		require.NoError(t, p.Validate(ctx, "r", "étéétéétééte", user))
	})

	t.Run("realm setting, with the NIST floor of 8", func(t *testing.T) {
		p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{MinPasswordLength: 16}})
		require.Equal(t, 16, p.MinLength(ctx, "r"))
		require.ErrorIs(t, p.Validate(ctx, "r", "fifteen chars!!", user), service.ErrPasswordTooShort)

		low := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{MinPasswordLength: 4}})
		require.Equal(t, 8, low.MinLength(ctx, "r"), "a realm cannot go below 8")
	})

	t.Run("maximum length", func(t *testing.T) {
		p := service.NewPasswordPolicyService(nil)
		require.NoError(t, p.Validate(ctx, "r", strings.Repeat("a", service.MaxPasswordLength), user))
		require.ErrorIs(t, p.Validate(ctx, "r", strings.Repeat("a", service.MaxPasswordLength+1), user), service.ErrPasswordTooLong)
	})

	t.Run("not the username or the e-mail", func(t *testing.T) {
		p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{MinPasswordLength: 4}})
		require.ErrorIs(t, p.Validate(ctx, "r", "ERIN@EXAMPLE.TEST", user), service.ErrPasswordMatchesIdentity)
		require.ErrorIs(t, p.Validate(ctx, "r", "erin    ", &domain.User{Username: "erin"}), service.ErrPasswordMatchesIdentity, "spaces around do not hide it")
		require.NoError(t, p.Validate(ctx, "r", "erin's own long passphrase", user))
	})

	t.Run("the breach check is on by default", func(t *testing.T) {
		require.True(t, service.DefaultInstanceSettings("r").PasswordBreachCheckEnabled)
	})

	t.Run("common passwords are refused, whatever the case", func(t *testing.T) {
		p := service.NewPasswordPolicyService(nil)
		require.ErrorIs(t, p.Validate(ctx, "r", "qwertyuiop123", user), service.ErrPasswordCompromised)
		require.ErrorIs(t, p.Validate(ctx, "r", "PassWord1234", user), service.ErrPasswordCompromised)
		require.NoError(t, p.Validate(ctx, "r", "qwertyuiop1234567", user))
	})

	t.Run("the breach checker, only when the realm turns it on", func(t *testing.T) {
		fake := &fakeBreach{pwned: map[string]bool{"a leaked passphrase": true}}
		newPolicy := func(on bool) *service.PasswordPolicyService {
			p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordBreachCheckEnabled: on}})
			p.Breach = fake
			return p
		}

		require.NoError(t, newPolicy(false).Validate(ctx, "r", "a leaked passphrase", user))
		require.Zero(t, fake.calls, "off: nothing is asked")

		p := newPolicy(true)
		require.ErrorIs(t, p.Validate(ctx, "r", "a leaked passphrase", user), service.ErrPasswordCompromised)
		require.NoError(t, p.Validate(ctx, "r", "never seen anywhere", user))
		require.Equal(t, 2, fake.calls)

		// No checker (unit tests, tools): the realm setting alone asks nothing.
		none := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordBreachCheckEnabled: true}})
		require.NoError(t, none.Validate(ctx, "r", "a leaked passphrase", user))
	})

	t.Run("the breach checker down: the password is accepted", func(t *testing.T) {
		p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordBreachCheckEnabled: true}})
		p.Breach = &fakeBreach{err: errors.New("timeout")}
		require.NoError(t, p.Validate(ctx, "r", "a leaked passphrase", user))
		require.ErrorIs(t, p.Validate(ctx, "r", "password1234", user), service.ErrPasswordCompromised, "the local list still applies")
	})

	t.Run("history: the last N passwords are refused, the current one included", func(t *testing.T) {
		u := &domain.User{
			RealmID: "r", Username: "erin", PasswordHash: legacyHash(t, "current passphrase"),
			PasswordHistory: []string{legacyHash(t, "previous passphrase"), legacyHash(t, "oldest passphrase")},
		}
		p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordHistoryCount: 2}})
		require.ErrorIs(t, p.Validate(ctx, "r", "current passphrase", u), service.ErrPasswordReused)
		require.ErrorIs(t, p.Validate(ctx, "r", "previous passphrase", u), service.ErrPasswordReused)
		require.NoError(t, p.Validate(ctx, "r", "oldest passphrase", u), "the 3rd one is beyond the last 2")
		require.NoError(t, p.Validate(ctx, "r", "a fresh passphrase", u))

		off := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{}})
		require.NoError(t, off.Validate(ctx, "r", "previous passphrase", u), "off by default")
	})

	t.Run("history: what a change keeps", func(t *testing.T) {
		u := &domain.User{RealmID: "r", PasswordHash: "h3", PasswordHistory: []string{"h2", "h1"}}
		now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

		upd := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordHistoryCount: 3}}).PasswordChange(ctx, u, "h4", now)
		require.Equal(t, "h4", *upd.PasswordHash)
		require.Equal(t, now, *upd.PasswordChangedAt)
		require.Equal(t, []string{"h3", "h2"}, *upd.PasswordHistory, "with h4 itself: the last 3")

		off := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{}}).PasswordChange(ctx, u, "h4", now)
		require.NotNil(t, off.PasswordHistory)
		require.Empty(t, *off.PasswordHistory, "off: what was kept is dropped")

		first := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordHistoryCount: 3}}).PasswordChange(ctx, &domain.User{RealmID: "r"}, "h1", now)
		require.Empty(t, *first.PasswordHistory, "no password before: nothing to keep")
	})

	t.Run("expiry", func(t *testing.T) {
		now := time.Now()
		changed := func(daysAgo int) *domain.User {
			return &domain.User{RealmID: "r", PasswordChangedAt: now.AddDate(0, 0, -daysAgo)}
		}
		p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordExpiryDays: 90}})
		require.False(t, p.PasswordExpired(ctx, changed(89), now))
		require.True(t, p.PasswordExpired(ctx, changed(91), now))
		require.False(t, p.PasswordExpired(ctx, &domain.User{RealmID: "r"}, now), "no change time known: never expires")
		require.False(t, service.NewPasswordPolicyService(nil).PasswordExpired(ctx, changed(1000), now), "0: never")
	})

	t.Run("the error carries the limits", func(t *testing.T) {
		p := service.NewPasswordPolicyService(nil)
		err := p.Validate(ctx, "r", "short", nil)
		var perr *service.PasswordPolicyError
		require.ErrorAs(t, err, &perr)
		require.Equal(t, 12, perr.MinLength)
		require.Equal(t, service.MaxPasswordLength, perr.MaxLength)
	})
}

// fakeBreach is a PasswordBreachChecker: pwned says which passwords leaked.
type fakeBreach struct {
	pwned map[string]bool
	err   error
	calls int
}

func (f *fakeBreach) Pwned(_ context.Context, password string) (bool, error) {
	f.calls++
	return f.pwned[password], f.err
}
