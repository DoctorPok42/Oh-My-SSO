package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/passkey/passkeytest"
)

// Step 18d: "Don't ask again on this device".

// fakeRisk answers SignInRisk with fixed reasons (or an error).
type fakeRisk struct {
	reasons []string
	err     error
	calls   int
}

func (r *fakeRisk) SignInRisk(context.Context, *domain.Session) ([]string, error) {
	r.calls++
	return r.reasons, r.err
}

const laptop = "laptop-device-hash"

func (f *mfaFixture) beginOn(t *testing.T, userID, clientRef, device string) *service.LoginDecision {
	t.Helper()
	dec, err := f.mfa.BeginLogin(context.Background(), service.BeginLoginInput{
		User: f.user(userID), Client: f.client(clientRef), IPAddress: "203.0.113.9", UserAgent: "Firefox/140", DeviceFingerprint: device,
	})
	require.NoError(t, err)
	return dec
}

// trustLaptop: alice (with an authenticator app) signs in on the laptop and
// ticks the box. It returns the TOTP secret.
func (f *mfaFixture) trustLaptop(t *testing.T) string {
	t.Helper()
	secret, _ := f.enrollTOTP(t, aliceID)
	dec := f.beginOn(t, aliceID, "", laptop)
	require.Equal(t, service.LoginMFARequired, dec.Outcome)
	require.Positive(t, dec.TrustDeviceDays, "the box is offered")
	res, err := f.mfa.VerifyLogin(context.Background(), service.VerifyLoginInput{
		RealmID: realmA, ChallengeToken: dec.ChallengeToken, Method: "totp", Code: totpAt(t, secret, f.now),
		IPAddress: "203.0.113.9", UserAgent: "Firefox/140", TrustDevice: true,
	})
	require.NoError(t, err)
	require.True(t, res.DeviceTrusted)
	f.advance(30 * time.Second)
	return secret
}

func TestTrustedDevice_SkipsTheSecondFactor(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)
	f.trustLaptop(t)

	d, err := f.devices.Get(ctx, aliceID, laptop)
	require.NoError(t, err)
	require.Equal(t, f.now.Add(-30*time.Second).Add(30*24*time.Hour), d.ExpiresAt, "fixed: 30 days from the box")
	require.Contains(t, f.audit.actions(), "mfa_device_trusted")

	dec := f.beginOn(t, aliceID, "", laptop)
	require.Equal(t, service.LoginAuthenticated, dec.Outcome, "no second factor on the trusted laptop")
	require.True(t, dec.TrustedDevice)
	require.Empty(t, dec.ChallengeToken)
	require.Equal(t, 1, f.risk.calls, "the sign-in was judged first")

	used, err := f.devices.Get(ctx, aliceID, laptop)
	require.NoError(t, err)
	require.Equal(t, f.now, used.LastUsedAt)
	require.Equal(t, d.ExpiresAt, used.ExpiresAt, "using it does not extend it")

	t.Run("another device still asks", func(t *testing.T) {
		require.Equal(t, service.LoginMFARequired, f.beginOn(t, aliceID, "", "phone-device-hash").Outcome)
	})
	t.Run("no device cookie: asks, no box", func(t *testing.T) {
		dec := f.beginOn(t, aliceID, "", "")
		require.Equal(t, service.LoginMFARequired, dec.Outcome)
		require.Zero(t, dec.TrustDeviceDays)
	})
	t.Run("an application that requires MFA still asks, without the box", func(t *testing.T) {
		dec := f.beginOn(t, aliceID, mfaClientStrict, laptop)
		require.Equal(t, service.LoginMFARequired, dec.Outcome)
		require.Zero(t, dec.TrustDeviceDays)
	})
	t.Run("a trusted sign-in is never MFA-verified", func(t *testing.T) {
		_, sess, err := f.sessionSvc.Create(ctx, service.CreateSessionInput{RealmID: realmA, UserID: aliceID,
			AuthMethod: domain.AuthMethodPassword, TrustedDevice: true})
		require.NoError(t, err)
		require.True(t, sess.TrustedDevice)
		require.False(t, sess.MFAVerified)
		var mfaErr interface{ Unwrap() error }
		_, err = f.core.IssueIdentityAssertion(ctx, sess.ID, mfaClientStrict, nil)
		require.ErrorAs(t, err, &mfaErr, "the strict application asks for a step-up")
	})
}

func TestTrustedDevice_Expiry(t *testing.T) {
	f := newMFAFixture(t)
	f.trustLaptop(t)
	f.advance(29 * 24 * time.Hour)
	require.Equal(t, service.LoginAuthenticated, f.beginOn(t, aliceID, "", laptop).Outcome, "day 29: trusted")
	f.advance(24 * time.Hour)
	require.Equal(t, service.LoginMFARequired, f.beginOn(t, aliceID, "", laptop).Outcome, "day 30: over")
}

func TestTrustedDevice_RealmPolicy(t *testing.T) {
	t.Run("off: no box, an existing trust is ignored", func(t *testing.T) {
		f := newMFAFixture(t)
		f.trustLaptop(t)
		f.settings.set(realmA, func(s *domain.InstanceSettings) { s.MFATrustedDeviceEnabled = false })
		dec := f.beginOn(t, aliceID, "", laptop)
		require.Equal(t, service.LoginMFARequired, dec.Outcome)
		require.Zero(t, dec.TrustDeviceDays)
	})
	t.Run("days of the realm", func(t *testing.T) {
		f := newMFAFixture(t)
		f.settings.set(realmA, func(s *domain.InstanceSettings) { s.MFATrustedDeviceDays = 7 })
		start := f.now
		f.trustLaptop(t)
		d, err := f.devices.Get(context.Background(), aliceID, laptop)
		require.NoError(t, err)
		require.True(t, d.ExpiresAt.Sub(start) < 8*24*time.Hour, "7 days")
	})
	t.Run("the box on an application that requires MFA is ignored", func(t *testing.T) {
		f := newMFAFixture(t)
		secret, _ := f.enrollTOTP(t, aliceID)
		dec := f.beginOn(t, aliceID, mfaClientStrict, laptop)
		res, err := f.mfa.VerifyLogin(context.Background(), service.VerifyLoginInput{
			RealmID: realmA, ChallengeToken: dec.ChallengeToken, Method: "totp", Code: totpAt(t, secret, f.now), TrustDevice: true,
		})
		require.NoError(t, err)
		require.False(t, res.DeviceTrusted)
	})
	t.Run("set through the realm policy, 1 to 90 days", func(t *testing.T) {
		f := newMFAFixture(t)
		ctx := context.Background()
		off, days := false, 14
		s, err := f.policy.SetRealmPolicy(ctx, service.SetRealmMFAPolicyInput{RealmID: realmA, TrustedDevices: &off, TrustedDeviceDays: &days})
		require.NoError(t, err)
		require.False(t, s.MFATrustedDeviceEnabled)
		require.Equal(t, 14, s.MFATrustedDeviceDays)
		for _, bad := range []int{0, 91} {
			_, err := f.policy.SetRealmPolicy(ctx, service.SetRealmMFAPolicyInput{RealmID: realmA, TrustedDeviceDays: &bad})
			require.ErrorIs(t, err, service.ErrInvalidMFAPolicy)
		}
		on, _ := f.trusted.Policy(ctx, realmA)
		require.False(t, on)
		on = true
		_, err = f.policy.SetRealmPolicy(ctx, service.SetRealmMFAPolicyInput{RealmID: realmA, TrustedDevices: &on})
		require.NoError(t, err)
		on, period := f.trusted.Policy(ctx, realmA)
		require.True(t, on)
		require.Equal(t, 14*24*time.Hour, period)
	})
}

func TestTrustedDevice_SuspiciousSignInAsks(t *testing.T) {
	f := newMFAFixture(t)
	f.trustLaptop(t)

	f.risk.reasons = []string{domain.SuspiciousNewCountry}
	dec := f.beginOn(t, aliceID, "", laptop)
	require.Equal(t, service.LoginMFARequired, dec.Outcome, "a new country: the second factor again")
	require.Equal(t, 30, dec.TrustDeviceDays)
	last := f.audit.entries[len(f.audit.entries)-1]
	require.Equal(t, "mfa_trusted_device_challenged", last.Action)
	require.Equal(t, []string{domain.SuspiciousNewCountry}, last.Details["reasons"])

	f.risk.reasons, f.risk.err = nil, errors.New("history unavailable")
	require.Equal(t, service.LoginMFARequired, f.beginOn(t, aliceID, "", laptop).Outcome, "cannot judge: ask")

	f.risk.err = nil
	require.Equal(t, service.LoginAuthenticated, f.beginOn(t, aliceID, "", laptop).Outcome, "normal again: trusted")
}

func TestTrustedDevice_PasskeySecondFactor(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)
	phone := passkeytest.New(testOrigin)
	f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
	dec := f.beginOn(t, aliceID, "", laptop)
	options, err := f.mfa.BeginPasskeyLogin(ctx, realmA, dec.ChallengeToken)
	require.NoError(t, err)
	response, err := phone.Get(options)
	require.NoError(t, err)
	res, err := f.mfa.FinishPasskeyLogin(ctx, service.VerifyPasskeyLoginInput{RealmID: realmA, ChallengeToken: dec.ChallengeToken,
		Response: response, TrustDevice: true})
	require.NoError(t, err)
	require.True(t, res.DeviceTrusted)
	require.Equal(t, service.LoginAuthenticated, f.beginOn(t, aliceID, "", laptop).Outcome)
}

func TestTrustedDevice_Revocation(t *testing.T) {
	ctx := context.Background()

	t.Run("every session revoked: every trust goes", func(t *testing.T) {
		f := newMFAFixture(t)
		f.trustLaptop(t)
		sessions := service.NewSessionService(f.sessions, f.settings, &fakeTokenRepo{byJTI: map[string]*domain.Token{}}, fakeSessionCache{},
			service.WithClock(f.clock), service.WithRevocationObserver(f.trusted))
		require.NoError(t, sessions.RevokeAllForUser(ctx, aliceID, domain.SessionRevokedPasswordReset))
		_, err := f.devices.Get(ctx, aliceID, laptop)
		require.Error(t, err)
		last := f.audit.entries[len(f.audit.entries)-1]
		require.Equal(t, "mfa_device_trust_revoked", last.Action)
		require.Equal(t, "password_reset", last.Details["reason"])
		require.Equal(t, service.LoginMFARequired, f.beginOn(t, aliceID, "", laptop).Outcome)
	})

	t.Run("one device, by an admin", func(t *testing.T) {
		f := newMFAFixture(t)
		f.trustLaptop(t)
		list, err := f.trusted.List(ctx, aliceID)
		require.NoError(t, err)
		require.Len(t, list, 1)
		require.ErrorIs(t, f.trusted.RevokeOne(ctx, bobID, list[0].ID), service.ErrTrustedDeviceNotFound, "not bob's")
		require.NoError(t, f.trusted.RevokeOne(ctx, aliceID, list[0].ID))
		list, err = f.trusted.List(ctx, aliceID)
		require.NoError(t, err)
		require.Empty(t, list)
	})

	t.Run("Forget on the tile", func(t *testing.T) {
		f := newMFAFixture(t)
		f.trustLaptop(t)
		require.NoError(t, f.trusted.RevokeDevice(ctx, realmA, aliceID, laptop, service.TrustRevokedForget))
		require.Equal(t, service.LoginMFARequired, f.beginOn(t, aliceID, "", laptop).Outcome)
	})
}
