package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// changeSettings: the realm's settings, e-mail change on or off.
type changeSettings struct {
	repository.InstanceSettingsRepository
	allowed *bool
}

func (s changeSettings) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	st := service.DefaultInstanceSettings(realmID)
	st.EmailChangeAllowed = *s.allowed
	return st, nil
}

type changeFixture struct {
	*verifyFixture
	allowed bool
}

// newChangeFixture: erin (realm-a) may change her address; frank, of the
// same realm, signs in as "frank" or frank@example.test.
func newChangeFixture() *changeFixture {
	f := &changeFixture{verifyFixture: newVerifyFixture(), allowed: true}
	frank := &domain.User{ID: "u-frank", RealmID: "realm-a", Username: "frank", Email: "frank@example.test", Status: domain.UserActive}
	f.users.byID[frank.ID] = frank
	f.setAllowed(true)
	return f
}

// setAllowed changes the realm's setting and starts a new service: the
// settings are cached for a minute.
func (f *changeFixture) setAllowed(on bool) {
	f.allowed = on
	f.svc = service.NewEmailVerificationService(service.EmailVerificationDeps{
		Tx: repository.NoTransaction{}, Users: f.users, Links: f.links, Notifier: f.notifier, Audit: f.audit,
		Settings: changeSettings{allowed: &f.allowed}, Now: f.clock.Now,
	})
}

// request asks for newEmail as erin and returns the link e-mailed to it.
func (f *changeFixture) request(t *testing.T, newEmail string) string {
	t.Helper()
	_, err := f.svc.RequestEmailChange(context.Background(), f.users.get("u-erin"), newEmail, self)
	require.NoError(t, err)
	e := f.notifier.last()
	require.Equal(t, domain.NotificationEmailVerification, e.Kind)
	return e.ResetToken
}

func TestEmailChange_ConfirmedLinkSwitchesTheAddress(t *testing.T) {
	f := newChangeFixture()
	ctx := context.Background()
	token := f.request(t, " Erin@New.Example ")

	require.Equal(t, "erin@new.example", f.notifier.last().To, "the link goes to the new address")
	u := f.users.get("u-erin")
	require.Equal(t, "erin@example.test", u.Email, "applications keep the old address until it is confirmed")
	require.Equal(t, "erin@new.example", u.PendingEmail)

	u, err := f.svc.Verify(ctx, "realm-a", token, "203.0.113.9", "test")
	require.NoError(t, err)
	require.Equal(t, "erin@new.example", u.Email)
	require.Empty(t, u.PendingEmail)
	require.NotNil(t, u.EmailVerifiedAt, "the link proved the new address")

	told := f.notifier.last()
	require.Equal(t, domain.NotificationEmailChanged, told.Kind)
	require.Equal(t, "erin@example.test", told.To, "the previous address is told")

	var actions []string
	for _, e := range f.audit.entries {
		actions = append(actions, e.Action)
	}
	require.Equal(t, []string{audit.UserEmailChangeRequested, audit.UserEmailChanged}, actions)

	_, err = f.svc.Verify(ctx, "realm-a", token, "", "")
	require.ErrorIs(t, err, service.ErrEmailVerificationInvalid, "a link works once")
}

func TestEmailChange_Refused(t *testing.T) {
	f := newChangeFixture()
	ctx := context.Background()
	erin := f.users.get("u-erin")
	for _, c := range []struct {
		email string
		want  error
	}{
		{"not an address", service.ErrInvalidEmail},
		{"Erin <erin@new.example>", service.ErrInvalidEmail},
		{"ERIN@example.test", service.ErrEmailUnchanged},
		{"frank@example.test", service.ErrEmailTaken},
		{"frank", service.ErrInvalidEmail},
	} {
		_, err := f.svc.RequestEmailChange(ctx, erin, c.email, self)
		require.ErrorIs(t, err, c.want, c.email)
	}
	// frank's username is an address: erin cannot take it either (the
	// sign-in form takes both in one field).
	f.users.byID["u-frank"].Username = "boss@example.test"
	_, err := f.svc.RequestEmailChange(ctx, erin, "boss@example.test", self)
	require.ErrorIs(t, err, service.ErrEmailTaken)

	f.setAllowed(false)
	_, err = f.svc.RequestEmailChange(ctx, erin, "erin@new.example", self)
	require.ErrorIs(t, err, service.ErrEmailChangeNotAllowed)
	require.Empty(t, f.notifier.events, "no e-mail for a refused change")
}

// The link of a change cancelled, replaced or overtaken proves nothing.
func TestEmailChange_StaleLinks(t *testing.T) {
	ctx := context.Background()

	t.Run("cancelled", func(t *testing.T) {
		f := newChangeFixture()
		token := f.request(t, "erin@new.example")
		require.NoError(t, f.svc.CancelEmailChange(ctx, f.users.get("u-erin"), self))
		require.Empty(t, f.users.get("u-erin").PendingEmail)
		_, err := f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
		require.Equal(t, "erin@example.test", f.users.get("u-erin").Email)
	})

	t.Run("replaced by another address", func(t *testing.T) {
		f := newChangeFixture()
		first := f.request(t, "erin@new.example")
		f.clock.Advance(time.Minute)
		f.request(t, "erin@other.example")
		_, err := f.svc.Verify(ctx, "realm-a", first, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
		require.Equal(t, "erin@other.example", f.users.get("u-erin").PendingEmail)
	})

	t.Run("address changed by an administrator", func(t *testing.T) {
		f := newChangeFixture()
		token := f.request(t, "erin@new.example")
		admin := "erin@corp.example"
		_, err := f.users.Update(ctx, "u-erin", repository.UpdateUserParams{Email: &admin})
		require.NoError(t, err)
		_, err = f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
		require.Equal(t, admin, f.users.get("u-erin").Email)
	})

	t.Run("verification e-mail for the current address", func(t *testing.T) {
		f := newChangeFixture()
		token := f.request(t, "erin@new.example")
		f.clock.Advance(time.Minute)
		f.send(t)
		require.Empty(t, f.users.get("u-erin").PendingEmail, "the new link cancels the change")
		_, err := f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	})

	t.Run("turned off since", func(t *testing.T) {
		f := newChangeFixture()
		token := f.request(t, "erin@new.example")
		f.setAllowed(false)
		_, err := f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
	})

	t.Run("address taken since", func(t *testing.T) {
		f := newChangeFixture()
		token := f.request(t, "erin@new.example")
		f.users.byID["u-frank"].Email = "erin@new.example"
		_, err := f.svc.Verify(ctx, "realm-a", token, "", "")
		require.ErrorIs(t, err, service.ErrEmailVerificationInvalid)
		require.Equal(t, "erin@example.test", f.users.get("u-erin").Email)
	})
}

func TestEmailChange_OneRequestAMinute(t *testing.T) {
	f := newChangeFixture()
	f.request(t, "erin@new.example")
	_, err := f.svc.RequestEmailChange(context.Background(), f.users.get("u-erin"), "erin@other.example", self)
	require.ErrorIs(t, err, service.ErrEmailVerificationTooSoon)
}
