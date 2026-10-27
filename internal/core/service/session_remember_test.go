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
)

// "Keep me signed in" (remembered sessions): durations, fallbacks when the
// realm turns the option off or its settings cannot be read, validation.

const day = 24 * time.Hour

// settingsStub returns st, or err when set (nil st and nil err: no row).
type settingsStub struct {
	repository.InstanceSettingsRepository
	st  *domain.InstanceSettings
	err error
}

func (s settingsStub) GetByRealmID(context.Context, string) (*domain.InstanceSettings, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.st == nil {
		return nil, repository.ErrNotFound
	}
	cp := *s.st
	return &cp, nil
}

// realmSettings: the defaults of a new realm, remember-me on or off.
func realmSettings(remember bool) *domain.InstanceSettings {
	st := service.DefaultInstanceSettings(realmA)
	st.RememberMeEnabled = remember
	return st
}

type rememberFixture struct {
	now      time.Time
	sessions *fakeSessionRepo
}

func newRememberFixture() *rememberFixture {
	f := &rememberFixture{now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	f.sessions = &fakeSessionRepo{now: f.clock, byID: map[string]*domain.Session{}}
	return f
}

func (f *rememberFixture) clock() time.Time        { return f.now }
func (f *rememberFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// service builds a SessionService on the shared session store. A new one
// per settings change: the real one caches the policy for a minute.
func (f *rememberFixture) service(settings settingsStub) *service.SessionService {
	return service.NewSessionService(f.sessions, settings, &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
		fakeSessionCache{}, service.WithClock(f.clock))
}

func (f *rememberFixture) login(t *testing.T, svc *service.SessionService, remember bool) (string, *domain.Session) {
	t.Helper()
	raw, sess, err := svc.Create(context.Background(), service.CreateSessionInput{
		RealmID: realmA, UserID: aliceID, AuthMethod: domain.AuthMethodPassword, RememberMe: remember,
	})
	require.NoError(t, err)
	return raw, sess
}

func TestRememberMe_Create(t *testing.T) {
	t.Run("ticked in a realm that offers it: long-lived session", func(t *testing.T) {
		f := newRememberFixture()
		_, sess := f.login(t, f.service(settingsStub{st: realmSettings(true)}), true)
		require.True(t, sess.RememberMe)
		require.Equal(t, f.now.Add(30*day), sess.ExpiresAt)
	})

	t.Run("not ticked: normal session", func(t *testing.T) {
		f := newRememberFixture()
		_, sess := f.login(t, f.service(settingsStub{st: realmSettings(true)}), false)
		require.False(t, sess.RememberMe)
		require.Equal(t, f.now.Add(8*time.Hour), sess.ExpiresAt)
	})

	t.Run("ticked in a realm that does not offer it: ignored", func(t *testing.T) {
		f := newRememberFixture()
		_, sess := f.login(t, f.service(settingsStub{st: realmSettings(false)}), true)
		require.False(t, sess.RememberMe)
		require.Equal(t, f.now.Add(8*time.Hour), sess.ExpiresAt)
	})

	t.Run("no settings row: the defaults, option offered", func(t *testing.T) {
		f := newRememberFixture()
		_, sess := f.login(t, f.service(settingsStub{}), true)
		require.True(t, sess.RememberMe)
	})

	t.Run("settings unreadable: no new remembered session", func(t *testing.T) {
		f := newRememberFixture()
		_, sess := f.login(t, f.service(settingsStub{err: errors.New("db down")}), true)
		require.False(t, sess.RememberMe)
	})

	t.Run("custom durations of the realm", func(t *testing.T) {
		f := newRememberFixture()
		st := realmSettings(true)
		st.RememberMeMaxDays, st.RememberMeIdleDays = 14, 3
		_, sess := f.login(t, f.service(settingsStub{st: st}), true)
		require.Equal(t, f.now.Add(14*day), sess.ExpiresAt)
	})
}

func TestRememberMe_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("a remembered session survives days without use, until its idle timeout", func(t *testing.T) {
		f := newRememberFixture()
		svc := f.service(settingsStub{st: realmSettings(true)})
		raw, _ := f.login(t, svc, true)

		f.advance(6 * day)
		_, err := svc.Validate(ctx, realmA, raw)
		require.NoError(t, err, "6 days idle < 7 days")

		f.advance(7*day + time.Minute)
		_, err = svc.Validate(ctx, realmA, raw)
		require.ErrorIs(t, err, service.ErrSessionInvalid, "7 days idle: gone")
	})

	t.Run("a normal session still ends after 10 minutes idle", func(t *testing.T) {
		f := newRememberFixture()
		svc := f.service(settingsStub{st: realmSettings(true)})
		raw, _ := f.login(t, svc, false)

		f.advance(11 * time.Minute)
		_, err := svc.Validate(ctx, realmA, raw)
		require.ErrorIs(t, err, service.ErrSessionInvalid)
	})

	t.Run("a remembered session used every day ends at its maximum duration", func(t *testing.T) {
		f := newRememberFixture()
		svc := f.service(settingsStub{st: realmSettings(true)})
		raw, _ := f.login(t, svc, true)

		for i := 0; i < 29; i++ {
			f.advance(day)
			_, err := svc.Validate(ctx, realmA, raw)
			require.NoError(t, err, "day %d", i+1)
		}
		f.advance(day)
		_, err := svc.Validate(ctx, realmA, raw)
		require.ErrorIs(t, err, service.ErrSessionInvalid, "30 days: gone")
	})

	t.Run("option turned off: remembered sessions get the normal idle timeout", func(t *testing.T) {
		f := newRememberFixture()
		raw, _ := f.login(t, f.service(settingsStub{st: realmSettings(true)}), true)

		off := f.service(settingsStub{st: realmSettings(false)})
		f.advance(5 * time.Minute)
		_, err := off.Validate(ctx, realmA, raw)
		require.NoError(t, err)

		f.advance(11 * time.Minute)
		_, err = off.Validate(ctx, realmA, raw)
		require.ErrorIs(t, err, service.ErrSessionInvalid)
	})

	t.Run("option turned off: remembered sessions get the normal lifetime", func(t *testing.T) {
		f := newRememberFixture()
		raw, _ := f.login(t, f.service(settingsStub{st: realmSettings(true)}), true)

		off := f.service(settingsStub{st: realmSettings(false)})
		for elapsed := time.Duration(0); elapsed < 7*time.Hour+55*time.Minute; elapsed += 5 * time.Minute {
			f.advance(5 * time.Minute)
			_, err := off.Validate(ctx, realmA, raw)
			require.NoError(t, err)
		}
		f.advance(6 * time.Minute)
		_, err := off.Validate(ctx, realmA, raw)
		require.ErrorIs(t, err, service.ErrSessionInvalid, "8 hours: gone, like a normal session")
	})

	t.Run("settings unreadable: remembered sessions are kept", func(t *testing.T) {
		f := newRememberFixture()
		raw, sess := f.login(t, f.service(settingsStub{st: realmSettings(true)}), true)

		broken := f.service(settingsStub{err: errors.New("db down")})
		f.advance(day)
		_, err := broken.Validate(ctx, realmA, raw)
		require.NoError(t, err, "a hiccup must not end every remembered session")

		_, err = broken.GetActive(ctx, sess.ID)
		require.NoError(t, err)
	})

	t.Run("back-channel checks follow the same rules", func(t *testing.T) {
		f := newRememberFixture()
		svc := f.service(settingsStub{st: realmSettings(true)})
		_, sess := f.login(t, svc, true)

		f.advance(2 * day)
		_, err := svc.GetActive(ctx, sess.ID)
		require.NoError(t, err)
		f.advance(6 * day)
		_, err = svc.GetActive(ctx, sess.ID)
		require.ErrorIs(t, err, service.ErrSessionInvalid)
	})
}

func TestRememberMe_Option(t *testing.T) {
	ctx := context.Background()
	f := newRememberFixture()

	allowed, maxAge := f.service(settingsStub{st: realmSettings(true)}).RememberMeOption(ctx, realmA)
	require.True(t, allowed)
	require.Equal(t, 30*day, maxAge)

	allowed, _ = f.service(settingsStub{st: realmSettings(false)}).RememberMeOption(ctx, realmA)
	require.False(t, allowed)

	allowed, _ = f.service(settingsStub{err: errors.New("db down")}).RememberMeOption(ctx, realmA)
	require.False(t, allowed, "never offered while the settings cannot be read")
}

func TestSessionDurationsOf(t *testing.T) {
	d := service.SessionDurationsOf(nil)
	require.Equal(t, service.SessionDurations{
		MaxLifetime: 8 * time.Hour, IdleTimeout: 10 * time.Minute,
		RememberMe: true, RememberMeMaxLifetime: 30 * day, RememberMeIdleTimeout: 7 * day,
	}, d)

	st := realmSettings(false)
	st.SessionMaxHours, st.SessionIdleMinutes, st.RememberMeMaxDays, st.RememberMeIdleDays = 12, 30, 0, -1
	d = service.SessionDurationsOf(st)
	require.Equal(t, 12*time.Hour, d.MaxLifetime)
	require.Equal(t, 30*time.Minute, d.IdleTimeout)
	require.False(t, d.RememberMe)
	require.Equal(t, 30*day, d.RememberMeMaxLifetime, "zero falls back to the default")
	require.Equal(t, 7*day, d.RememberMeIdleTimeout, "negative falls back to the default")
}

func TestValidateSessionDurations(t *testing.T) {
	field := func(err error) string {
		var ae *service.AdminError
		require.ErrorAs(t, err, &ae)
		require.Equal(t, service.AdminInvalid, ae.Kind)
		return ae.Field
	}

	require.NoError(t, service.ValidateSessionDurations(realmSettings(true)), "the defaults are valid")

	st := realmSettings(true)
	st.RememberMeIdleDays, st.RememberMeMaxDays = 10, 5
	require.Equal(t, "remember_me_idle_days", field(service.ValidateSessionDurations(st)), "idle longer than the lifetime")

	st = realmSettings(true)
	st.SessionMaxHours, st.RememberMeMaxDays, st.RememberMeIdleDays = 72, 2, 1
	require.Equal(t, "remember_me_max_days", field(service.ValidateSessionDurations(st)), "shorter than a normal session")

	st = realmSettings(true)
	st.SessionIdleMinutes, st.RememberMeIdleDays = 3*24*60, 2
	require.Equal(t, "remember_me_idle_days", field(service.ValidateSessionDurations(st)), "idles out sooner than a normal session")

	st.RememberMeEnabled = false
	require.NoError(t, service.ValidateSessionDurations(st), "nothing to check while the option is off")
}

func TestRememberMe_SurvivesTheSecondFactor(t *testing.T) {
	f := newMFAFixture(t)
	secret, _ := f.enrollTOTP(t, aliceID)

	for _, remember := range []bool{true, false} {
		dec, err := f.mfa.BeginLogin(context.Background(), service.BeginLoginInput{
			User: f.user(aliceID), IPAddress: "203.0.113.9", UserAgent: "test", RememberMe: remember,
		})
		require.NoError(t, err)
		require.Equal(t, service.LoginMFARequired, dec.Outcome)

		res, err := f.verify(dec, "totp", totpAt(t, secret, f.now))
		require.NoError(t, err)
		require.Equal(t, remember, res.Session.RememberMe, "the choice made with the password is kept")
		require.True(t, res.Session.MFAVerified)
		f.advance(30 * time.Second) // next TOTP window: a code is never accepted twice
	}
}
