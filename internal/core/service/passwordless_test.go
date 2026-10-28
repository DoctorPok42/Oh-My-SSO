package service_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/mfastore"
	"sso.internal/sso/internal/passkey/passkeytest"
)

// Step 18c: sign-in without password with a passkey or a security key.

const mfaClientTOTP = "client-totp" // mfa required, authenticator app only

func (f *mfaFixture) addTOTPOnlyClient() {
	f.clients.mu.Lock()
	defer f.clients.mu.Unlock()
	f.clients.byID[mfaClientTOTP] = &domain.ClientApp{ID: mfaClientTOTP, RealmID: realmA, Protocol: domain.ClientAppProtocolOIDC,
		Status: domain.ClientAppActive, ClientID: mfaClientTOTP + "-id", IDTokenTTL: 300, SubjectType: domain.ClientAppSubjectPublic,
		MFAPolicy: domain.ClientAppMFARequired, MFAAllowedMethods: []domain.MfaMethodType{domain.MfaMethodTOTP}}
}

func (f *mfaFixture) client(ref string) *domain.ClientApp {
	if ref == "" {
		return nil
	}
	c, _ := f.clients.GetByID(context.Background(), ref)
	return c
}

// passwordless runs both halves of a sign-in without password. tileUser ""
// is a discoverable passkey (no tile).
func (f *mfaFixture) passwordless(t *testing.T, mfa *service.MFAService, tileUser, clientRef string, auth *passkeytest.Authenticator) (*service.VerifiedLogin, error) {
	t.Helper()
	ctx := context.Background()
	in := service.BeginPasswordlessInput{RealmID: realmA, Client: f.client(clientRef)}
	if tileUser != "" {
		in.User = f.user(tileUser)
	}
	c, err := mfa.BeginPasswordlessLogin(ctx, in)
	if err != nil {
		return nil, err
	}
	response, err := auth.Get(c.Options)
	require.NoError(t, err)
	return mfa.FinishPasswordlessLogin(ctx, service.FinishPasswordlessInput{
		RealmID: realmA, Token: c.Token, Response: response,
		IPAddress: "203.0.113.9", UserAgent: "test", DeviceFingerprint: "device-hash", RememberMe: true,
	})
}

func requestOptionsOf(t *testing.T, options []byte) (uv string, allowed int) {
	t.Helper()
	var o struct {
		PublicKey struct {
			UserVerification string            `json:"userVerification"`
			AllowCredentials []json.RawMessage `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(options, &o))
	return o.PublicKey.UserVerification, len(o.PublicKey.AllowCredentials)
}

func TestPasswordless_SignInMethods(t *testing.T) {
	ctx := context.Background()
	methods := func(f *mfaFixture, userID, clientRef string) []core.SignInMethod {
		m, err := f.mfa.SignInMethods(ctx, f.user(userID), f.client(clientRef))
		require.NoError(t, err)
		return m
	}

	t.Run("no factor: the password", func(t *testing.T) {
		f := newMFAFixture(t)
		require.Equal(t, []core.SignInMethod{core.SignInPassword}, methods(f, aliceID, ""))
	})

	t.Run("an authenticator app does not replace the password", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		require.Equal(t, []core.SignInMethod{core.SignInPassword}, methods(f, aliceID, ""))
	})

	t.Run("a passkey comes first", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		f.enrollPasskey(t, aliceID, passkeytest.New(testOrigin), service.PasskeyKindPasskey)
		require.Equal(t, []core.SignInMethod{core.SignInPasskey, core.SignInPassword}, methods(f, aliceID, ""))
		require.Equal(t, []core.SignInMethod{core.SignInPasskey, core.SignInPassword}, methods(f, aliceID, mfaClientPasskey))
	})

	t.Run("a security key (YubiKey) too", func(t *testing.T) {
		f := newMFAFixture(t)
		key := passkeytest.New(testOrigin)
		key.Discoverable = false
		m, _, _ := f.enrollPasskey(t, aliceID, key, service.PasskeyKindSecurityKey)
		require.Equal(t, domain.MfaMethodWebAuthn, m.Type)
		require.Equal(t, []core.SignInMethod{core.SignInPasskey, core.SignInPassword}, methods(f, aliceID, ""))
		require.Equal(t, []core.SignInMethod{core.SignInPassword}, methods(f, aliceID, mfaClientPasskey),
			"this application only accepts passkeys")
	})

	t.Run("an application that wants an authenticator app: password first", func(t *testing.T) {
		f := newMFAFixture(t)
		f.addTOTPOnlyClient()
		f.enrollPasskey(t, aliceID, passkeytest.New(testOrigin), service.PasskeyKindPasskey)
		require.Equal(t, []core.SignInMethod{core.SignInPassword}, methods(f, aliceID, mfaClientTOTP))
	})

	t.Run("second factors: passkey, security key, app, backup codes", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		f.enrollPasskey(t, aliceID, passkeytest.New(testOrigin), service.PasskeyKindPasskey)
		key := passkeytest.New(testOrigin)
		key.Discoverable = false
		f.enrollPasskey(t, aliceID, key, service.PasskeyKindSecurityKey)
		dec := f.beginLogin(t, aliceID, "")
		require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodWebAuthn, domain.MfaMethodTOTP, domain.MfaMethodBackupCodes}, dec.Methods)
	})
}

func TestPasswordless_SignIn(t *testing.T) {
	ctx := context.Background()

	t.Run("tile: the passkey alone signs in, two factors", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)

		c, err := f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA, User: f.user(aliceID)})
		require.NoError(t, err)
		uv, allowed := requestOptionsOf(t, c.Options)
		require.Equal(t, "required", uv, "the passkey replaces the password: the user must be verified")
		require.Equal(t, 1, allowed, "only the tile's credentials")

		response, err := phone.Get(c.Options)
		require.NoError(t, err)
		res, err := f.mfa.FinishPasswordlessLogin(ctx, service.FinishPasswordlessInput{
			RealmID: realmA, Token: c.Token, Response: response, IPAddress: "203.0.113.9", UserAgent: "test",
			DeviceFingerprint: "device-hash", RememberMe: true,
		})
		require.NoError(t, err)
		require.Equal(t, service.LoginAuthenticated, res.Outcome)
		require.Equal(t, aliceID, res.User.ID)
		s := res.Session
		require.Equal(t, domain.AuthMethodHardwareKey, s.AuthMethod)
		require.True(t, s.MFAVerified)
		require.Equal(t, "passkey", s.MFAMethodType)
		require.Equal(t, "device-hash", s.DeviceFingerprint)
		require.Equal(t, domain.LoginAttemptSuccess, f.attempts.last().Status)
		require.Equal(t, "alice", f.attempts.last().Identifier)

		a, err := f.core.IssueIdentityAssertion(ctx, s.ID, mfaClientPasskey, nil)
		require.NoError(t, err, "a passkey-only application accepts it")
		require.Equal(t, []string{"hwk", "mfa"}, a.AuthMethods)

		// The ceremony is single use: the same answer again finds nothing.
		_, err = f.mfa.FinishPasswordlessLogin(ctx, service.FinishPasswordlessInput{RealmID: realmA, Token: c.Token, Response: response})
		require.ErrorIs(t, err, service.ErrWebAuthnCeremonyInvalid)
	})

	t.Run("discoverable: the authenticator says who signs in", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		c, err := f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA})
		require.NoError(t, err)
		uv, allowed := requestOptionsOf(t, c.Options)
		require.Equal(t, "required", uv)
		require.Zero(t, allowed, "any passkey of the browser")
		res, err := f.passwordless(t, f.mfa, "", "", phone)
		require.NoError(t, err)
		require.Equal(t, aliceID, res.User.ID)
	})

	t.Run("a YubiKey with its PIN, from the tile", func(t *testing.T) {
		f := newMFAFixture(t)
		key := passkeytest.New(testOrigin)
		key.Discoverable = false
		f.enrollPasskey(t, aliceID, key, service.PasskeyKindSecurityKey)
		res, err := f.passwordless(t, f.mfa, aliceID, "", key)
		require.NoError(t, err)
		require.Equal(t, "webauthn", res.Session.MFAMethodType)
	})

	t.Run("no user verification: refused", func(t *testing.T) {
		f := newMFAFixture(t)
		key := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, key, service.PasskeyKindPasskey)
		key.UserVerification, key.IgnoreUserVerification = false, true // touched, no PIN
		_, err := f.passwordless(t, f.mfa, aliceID, "", key)
		require.ErrorIs(t, err, service.ErrPasskeySignInFailed)
		require.Equal(t, domain.LoginFailurePasskeyRejected, f.attempts.last().FailureReason)
	})

	t.Run("phishing site: refused", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		phone.SetOrigin("https://sso.test.evil.example")
		_, err := f.passwordless(t, f.mfa, "", "", phone)
		require.ErrorIs(t, err, service.ErrPasskeySignInFailed)
	})

	t.Run("cloned authenticator: refused and audited", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		_, err := f.passwordless(t, f.mfa, aliceID, "", phone)
		require.NoError(t, err)
		_, err = f.passwordless(t, f.mfa, aliceID, "", phone)
		require.NoError(t, err)
		phone.SetSignCount(0) // goes backwards: a copy of the key answers
		_, err = f.passwordless(t, f.mfa, aliceID, "", phone)
		require.ErrorIs(t, err, service.ErrPasskeySignInFailed)
		require.Contains(t, f.audit.actions(), "mfa_passkey_clone_warning")
	})

	t.Run("a passkey of another realm never signs in here", func(t *testing.T) {
		f := newMFAFixture(t)
		f.users.byID["user-carol"] = &domain.User{ID: "user-carol", RealmID: "realm-b", Username: "carol", Status: domain.UserActive}
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, "user-carol", phone, service.PasskeyKindPasskey)
		_, err := f.passwordless(t, f.mfa, "", "", phone)
		require.ErrorIs(t, err, service.ErrPasskeySignInFailed)
	})

	t.Run("suspended account: refused once the passkey is proven", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		c, err := f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA})
		require.NoError(t, err)
		f.users.byID[aliceID].Status = domain.UserSuspended
		response, err := phone.Get(c.Options)
		require.NoError(t, err)
		_, err = f.mfa.FinishPasswordlessLogin(ctx, service.FinishPasswordlessInput{RealmID: realmA, Token: c.Token, Response: response})
		require.ErrorIs(t, err, service.ErrAccountNotActive)
		require.Equal(t, domain.LoginFailureAccountLocked, f.attempts.last().FailureReason)

		// A tile of a suspended account offers nothing.
		_, err = f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA, User: f.user(aliceID)})
		require.ErrorIs(t, err, service.ErrNoPasskeyForSignIn)
	})

	t.Run("an active timeout blocks it, like after a password", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		blocked := service.NewMFAService(service.MFADeps{
			Users: f.users, Methods: f.methods, BackupCodes: f.codes, Sessions: f.sessionSvc, Policy: f.policy,
			Store: mfastore.NewMemory(f.clock), Limiter: f.limiter, LoginAttempts: f.attempts, Clients: f.clients,
			Passkeys: f.passkeys, Now: f.clock, Timeouts: &fakeTimeouts{blocked: true},
		})
		_, err := f.passwordless(t, blocked, aliceID, mfaClientPlain, phone)
		require.ErrorIs(t, err, service.ErrTimeoutActive)
		require.Equal(t, domain.LoginFailureTimeoutActive, f.attempts.last().FailureReason)
	})

	t.Run("expired ceremony", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		c, err := f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA})
		require.NoError(t, err)
		response, err := phone.Get(c.Options)
		require.NoError(t, err)
		f.advance(6 * time.Minute)
		_, err = f.mfa.FinishPasswordlessLogin(ctx, service.FinishPasswordlessInput{RealmID: realmA, Token: c.Token, Response: response})
		require.ErrorIs(t, err, service.ErrWebAuthnCeremonyInvalid)
	})

	t.Run("another realm's page cannot use the ceremony", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		c, err := f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA})
		require.NoError(t, err)
		response, err := phone.Get(c.Options)
		require.NoError(t, err)
		_, err = f.mfa.FinishPasswordlessLogin(ctx, service.FinishPasswordlessInput{RealmID: "realm-b", Token: c.Token, Response: response})
		require.ErrorIs(t, err, service.ErrWebAuthnCeremonyInvalid)
	})
}

func TestPasswordless_ApplicationPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("tile on a TOTP-only application: no passkey ceremony", func(t *testing.T) {
		f := newMFAFixture(t)
		f.addTOTPOnlyClient()
		f.enrollPasskey(t, aliceID, passkeytest.New(testOrigin), service.PasskeyKindPasskey)
		_, err := f.mfa.BeginPasswordlessLogin(ctx, service.BeginPasswordlessInput{RealmID: realmA, User: f.user(aliceID), Client: f.client(mfaClientTOTP)})
		require.ErrorIs(t, err, service.ErrNoPasskeyForSignIn)
	})

	t.Run("discoverable passkey on a TOTP-only application: signed in, the application asks for its method", func(t *testing.T) {
		f := newMFAFixture(t)
		f.addTOTPOnlyClient()
		f.access.clients[mfaClientTOTP] = activeClient(mfaClientTOTP, []string{"role-app"}, nil, nil)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)

		res, err := f.passwordless(t, f.mfa, "", mfaClientTOTP, phone)
		require.NoError(t, err)
		require.Equal(t, service.LoginMFAEnrollmentRequired, res.Outcome, "no authenticator app yet")
		_, err = f.core.IssueIdentityAssertion(ctx, res.Session.ID, mfaClientTOTP, nil)
		var mfaErr *core.MFARequiredError
		require.ErrorAs(t, err, &mfaErr)
		require.True(t, mfaErr.EnrollmentRequired)

		f.enrollTOTP(t, aliceID)
		res, err = f.passwordless(t, f.mfa, "", mfaClientTOTP, phone)
		require.NoError(t, err)
		require.Equal(t, service.LoginAuthenticated, res.Outcome, "a step-up with the app follows")
		_, err = f.core.IssueIdentityAssertion(ctx, res.Session.ID, mfaClientTOTP, nil)
		require.ErrorAs(t, err, &mfaErr)
		require.False(t, mfaErr.EnrollmentRequired)
	})
}
