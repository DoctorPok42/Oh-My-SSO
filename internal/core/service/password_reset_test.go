package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/lockoutstore"
)

// Step 12, Definition of Done (service level): valid token, expired token,
// token already used, unknown e-mail. The HTTP side ("same answer for an
// unknown e-mail", AuditLog notification_sent) is tested in
// internal/httpserver and internal/notify.

const resetRealm = "realm-reset"

type resetFixture struct {
	clock    *testClock
	users    *memUsers
	tokens   *memResetTokens
	sessions *fakeSessionRepo
	sessSvc  *service.SessionService
	notifier *recordingNotifier
	audit    *fakeAuditRepo
	lockout  *service.LockoutService
	svc      *service.PasswordResetService
	auth     *service.AuthService
	user     *domain.User
}

func newResetFixture(t *testing.T) *resetFixture {
	t.Helper()
	f := &resetFixture{clock: newTestClock(), notifier: &recordingNotifier{}, audit: &fakeAuditRepo{}}
	f.user = &domain.User{
		ID: "u-carol", RealmID: resetRealm, Username: "carol", Email: "carol@example.test",
		PasswordHash: alicePasswordHash(t), Status: domain.UserActive,
	}
	f.users = newMemUsers(f.user)
	f.tokens = newMemResetTokens()
	f.sessions = &fakeSessionRepo{now: f.clock.Now, byID: map[string]*domain.Session{}}
	f.sessSvc = service.NewSessionService(f.sessions, fakeSettingsRepo{}, &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
		fakeSessionCache{}, service.WithClock(f.clock.Now))
	f.lockout = service.NewLockoutService(service.LockoutDeps{
		Users: f.users, Unknown: lockoutstore.NewMemory(f.clock.Now), Now: f.clock.Now,
	})
	f.svc = service.NewPasswordResetService(service.PasswordResetDeps{
		Users:    f.users,
		Tokens:   f.tokens,
		Sessions: f.sessSvc,
		Lockout:  f.lockout,
		Notifier: f.notifier,
		Audit:    f.audit,
		Now:      f.clock.Now,
	})
	f.auth = service.NewAuthService(f.users, &fakeLoginAttemptRepo{})
	return f
}

// request asks for a link and returns the raw token found in the event.
func (f *resetFixture) request(t *testing.T, identifier string) string {
	t.Helper()
	require.NoError(t, f.svc.RequestReset(context.Background(), service.RequestResetInput{
		RealmID: resetRealm, Identifier: identifier, IPAddress: "203.0.113.5", UserAgent: "test",
	}))
	e := f.notifier.last()
	require.Equal(t, domain.NotificationPasswordReset, e.Kind)
	require.NotEmpty(t, e.ResetToken)
	return e.ResetToken
}

func (f *resetFixture) reset(token, password string) error {
	return f.svc.ResetPassword(context.Background(), service.ResetPasswordInput{
		RealmID: resetRealm, Token: token, NewPassword: password, IPAddress: "203.0.113.5",
	})
}

func (f *resetFixture) login(password string) error {
	_, err := f.auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
		RealmID: resetRealm, Identifier: "carol", Password: password,
	})
	return err
}

const newPassword = "a long and new passphrase"

func TestPasswordReset_DefinitionOfDone(t *testing.T) {
	t.Run("valid token: new password, every session revoked, token used up", func(t *testing.T) {
		f := newResetFixture(t)
		ctx := context.Background()
		// Two open sessions (two browsers) before the reset.
		_, s1, err := f.sessSvc.Create(ctx, service.CreateSessionInput{RealmID: resetRealm, UserID: f.user.ID})
		require.NoError(t, err)
		_, s2, err := f.sessSvc.Create(ctx, service.CreateSessionInput{RealmID: resetRealm, UserID: f.user.ID})
		require.NoError(t, err)

		token := f.request(t, "carol@example.test")
		stored, err := f.tokens.GetByTokenHash(ctx, service.HashResetToken(token))
		require.NoError(t, err, "only the SHA-256 of the token is stored")
		require.NotEqual(t, token, stored.TokenHash)
		require.Equal(t, f.clock.Now().Add(30*time.Minute), stored.ExpiresAt, "default lifetime: 30 minutes")
		require.Equal(t, "203.0.113.5", stored.RequestedIP)

		require.NoError(t, f.reset(token, newPassword))

		require.NoError(t, f.login(newPassword), "the new password works")
		require.ErrorIs(t, f.login(alicePassword), service.ErrInvalidCredentials, "the old one does not")
		for _, id := range []string{s1.ID, s2.ID} {
			s := f.sessions.byID[id]
			require.Equal(t, domain.SessionRevoked, s.Status)
			require.Equal(t, domain.SessionRevokedPasswordReset, s.RevokedReason)
		}
		used, err := f.tokens.GetByTokenHash(ctx, service.HashResetToken(token))
		require.NoError(t, err)
		require.True(t, used.Used)
		require.Equal(t, domain.NotificationPasswordChanged, f.notifier.last().Kind)
		require.Contains(t, f.audit.actions(), "password_reset")
	})

	t.Run("expired token is refused, password unchanged", func(t *testing.T) {
		f := newResetFixture(t)
		token := f.request(t, "carol")
		f.clock.Advance(30*time.Minute + time.Second)

		require.ErrorIs(t, f.reset(token, newPassword), service.ErrResetTokenInvalid)
		require.NoError(t, f.login(alicePassword))
	})

	t.Run("token already used is refused", func(t *testing.T) {
		f := newResetFixture(t)
		token := f.request(t, "carol")
		require.NoError(t, f.reset(token, newPassword))

		require.ErrorIs(t, f.reset(token, "yet another long passphrase"), service.ErrResetTokenInvalid)
		require.NoError(t, f.login(newPassword))
	})

	t.Run("unknown e-mail: no error, no token, no e-mail", func(t *testing.T) {
		f := newResetFixture(t)
		err := f.svc.RequestReset(context.Background(), service.RequestResetInput{
			RealmID: resetRealm, Identifier: "nobody@example.test",
		})
		require.NoError(t, err, "nothing tells the caller the account does not exist")
		require.Zero(t, f.tokens.count())
		require.Empty(t, f.notifier.kinds())
	})
}

func TestPasswordReset_Rules(t *testing.T) {
	t.Run("a new request cancels the previous link", func(t *testing.T) {
		f := newResetFixture(t)
		first := f.request(t, "carol")
		second := f.request(t, "carol")
		require.NotEqual(t, first, second)
		require.Equal(t, 1, f.tokens.count())
		require.ErrorIs(t, f.reset(first, newPassword), service.ErrResetTokenInvalid)
		require.NoError(t, f.reset(second, newPassword))
	})

	t.Run("a password refused by the policy keeps the link usable", func(t *testing.T) {
		f := newResetFixture(t)
		token := f.request(t, "carol")

		err := f.reset(token, "short")
		var perr *service.PasswordPolicyError
		require.ErrorAs(t, err, &perr)
		require.ErrorIs(t, err, service.ErrPasswordTooShort)
		require.Equal(t, 12, perr.MinLength)

		require.ErrorIs(t, f.reset(token, "carol@example.test"), service.ErrPasswordMatchesIdentity)
		require.NoError(t, f.reset(token, newPassword), "same link, better password")
	})

	t.Run("a link of one realm does not work in another", func(t *testing.T) {
		f := newResetFixture(t)
		token := f.request(t, "carol")
		err := f.svc.ResetPassword(context.Background(), service.ResetPasswordInput{
			RealmID: "another-realm", Token: token, NewPassword: newPassword,
		})
		require.ErrorIs(t, err, service.ErrResetTokenInvalid)
	})

	t.Run("garbage token", func(t *testing.T) {
		f := newResetFixture(t)
		require.ErrorIs(t, f.reset("", newPassword), service.ErrResetTokenInvalid)
		require.ErrorIs(t, f.reset("not-a-token", newPassword), service.ErrResetTokenInvalid)
	})

	t.Run("suspended account: no link sent", func(t *testing.T) {
		f := newResetFixture(t)
		suspended := domain.UserSuspended
		_, err := f.users.Update(context.Background(), f.user.ID, repository.UpdateUserParams{Status: &suspended})
		require.NoError(t, err)
		require.NoError(t, f.svc.RequestReset(context.Background(), service.RequestResetInput{RealmID: resetRealm, Identifier: "carol"}))
		require.Empty(t, f.notifier.kinds())
	})

	t.Run("the reset unlocks a locked account", func(t *testing.T) {
		f := newResetFixture(t)
		auth := service.NewAuthService(f.users, &fakeLoginAttemptRepo{}, service.WithLockout(f.lockout))
		for i := 0; i < 5; i++ {
			_, _ = auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
				RealmID: resetRealm, Identifier: "carol", Password: "wrong",
			})
		}
		_, err := auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
			RealmID: resetRealm, Identifier: "carol", Password: alicePassword,
		})
		require.True(t, errors.Is(err, service.ErrAccountLocked), "locked: %v", err)

		token := f.request(t, "carol")
		require.NoError(t, f.reset(token, newPassword))
		_, err = auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
			RealmID: resetRealm, Identifier: "carol", Password: newPassword,
		})
		require.NoError(t, err)
	})

	t.Run("password_reset_ttl_minutes of the realm", func(t *testing.T) {
		f := newResetFixture(t)
		settings := &memSettings{s: &domain.InstanceSettings{PasswordResetTTLMinutes: 5, MinPasswordLength: 12}}
		svc := service.NewPasswordResetService(service.PasswordResetDeps{
			Users: f.users, Tokens: f.tokens, Sessions: f.sessSvc, Settings: settings,
			Notifier: f.notifier, Now: f.clock.Now,
		})
		require.NoError(t, svc.RequestReset(context.Background(), service.RequestResetInput{RealmID: resetRealm, Identifier: "carol"}))
		e := f.notifier.last()
		require.Equal(t, f.clock.Now().Add(5*time.Minute), e.ExpiresAt)
	})
}
