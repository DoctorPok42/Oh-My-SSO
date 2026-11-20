package service_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // the Pwned Passwords range API is keyed by SHA-1
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	t.Run("the breach check is on by default, but never without a settings store", func(t *testing.T) {
		require.True(t, service.DefaultInstanceSettings("r").PasswordBreachCheckEnabled)
		require.Empty(t, service.NewPasswordPolicyService(nil).PwnedPasswordsURL)
	})

	t.Run("common passwords are refused, whatever the case", func(t *testing.T) {
		p := service.NewPasswordPolicyService(nil)
		require.ErrorIs(t, p.Validate(ctx, "r", "qwertyuiop123", user), service.ErrPasswordCompromised)
		require.ErrorIs(t, p.Validate(ctx, "r", "PassWord1234", user), service.ErrPasswordCompromised)
		require.NoError(t, p.Validate(ctx, "r", "qwertyuiop1234567", user))
	})

	t.Run("Have I Been Pwned, only when the realm turns it on", func(t *testing.T) {
		const leaked, padded = "a leaked passphrase", "a padded passphrase"
		var paths, padding []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			padding = append(padding, r.Header.Get("Add-Padding"))
			for _, line := range []struct {
				pw    string
				count int
			}{{leaked, 42}, {padded, 0}} {
				sum := fmt.Sprintf("%X", sha1.Sum([]byte(line.pw)))
				fmt.Fprintf(w, "%s:%d\r\n", sum[5:], line.count)
			}
		}))
		defer srv.Close()
		newPolicy := func(on bool) *service.PasswordPolicyService {
			p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordBreachCheckEnabled: on}})
			p.PwnedPasswordsURL = srv.URL + "/range/"
			return p
		}

		require.NoError(t, newPolicy(false).Validate(ctx, "r", leaked, user))
		require.Empty(t, paths, "off: nothing leaves the server")

		p := newPolicy(true)
		require.ErrorIs(t, p.Validate(ctx, "r", leaked, user), service.ErrPasswordCompromised)
		require.NoError(t, p.Validate(ctx, "r", padded, user), "a padding line (count 0) is not a breach")
		require.NoError(t, p.Validate(ctx, "r", "never seen anywhere", user))
		require.Len(t, paths, 3)
		sum := fmt.Sprintf("%X", sha1.Sum([]byte(leaked)))
		require.Equal(t, "/range/"+sum[:5], paths[0], "only the 5 first hex digits are sent")
		require.Equal(t, []string{"true", "true", "true"}, padding)
	})

	t.Run("Have I Been Pwned down: the password is accepted", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		p := service.NewPasswordPolicyService(&memSettings{s: &domain.InstanceSettings{PasswordBreachCheckEnabled: true}})
		p.PwnedPasswordsURL = srv.URL + "/range/"
		require.NoError(t, p.Validate(ctx, "r", "a leaked passphrase", user))
		require.ErrorIs(t, p.Validate(ctx, "r", "password1234", user), service.ErrPasswordCompromised, "the local list still applies")
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
