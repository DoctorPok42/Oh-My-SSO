package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/mfastore"
	"sso.internal/sso/internal/passkey/passkeytest"
)


func (f *mfaFixture) enrollPasskey(t *testing.T, userID string, auth *passkeytest.Authenticator, kind service.PasskeyKind) (*domain.MfaMethod, []string, *domain.Session) {
	t.Helper()
	ctx := context.Background()
	sess := f.passwordSession(t, userID)
	options, err := f.mfa.BeginPasskeyRegistration(ctx, f.user(userID), sess, kind, "my device")
	require.NoError(t, err)
	response, err := auth.Create(options)
	require.NoError(t, err)
	res, err := f.mfa.FinishPasskeyRegistration(ctx, f.user(userID), sess, response)
	require.NoError(t, err)
	return res.Method, res.BackupCodes, res.Session
}

func (f *mfaFixture) passkeyLogin(t *testing.T, dec *service.LoginDecision, auth *passkeytest.Authenticator) (*service.VerifiedLogin, error) {
	t.Helper()
	ctx := context.Background()
	options, err := f.mfa.BeginPasskeyLogin(ctx, realmA, dec.ChallengeToken)
	if err != nil {
		return nil, err
	}
	response, err := auth.Get(options)
	require.NoError(t, err)
	return f.mfa.FinishPasskeyLogin(ctx, service.VerifyPasskeyLoginInput{RealmID: realmA, ChallengeToken: dec.ChallengeToken, Response: response})
}

// TestMFA_PasskeyDefinitionOfDone: passkey enrollment -> login with the
// passkey as second factor.
func TestMFA_PasskeyDefinitionOfDone(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)
	phone := passkeytest.New(testOrigin)

	// 1. Enrollment.
	m, codes, sess := f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
	require.Equal(t, domain.MfaMethodPasskey, m.Type)
	require.True(t, m.IsDiscoverable)
	require.Equal(t, "my device", m.Name)
	require.NotEmpty(t, m.CredentialID)
	require.NotEmpty(t, m.WebAuthnCredential)
	require.Len(t, codes, 10, "first factor: backup codes")
	require.True(t, sess.MFAVerified)
	require.Equal(t, "passkey", sess.MFAMethodType)

	// 2. Login: the passkey answers the second step.
	dec := f.beginLogin(t, aliceID, "")
	require.Equal(t, service.LoginMFARequired, dec.Outcome)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodBackupCodes}, dec.Methods)

	res, err := f.passkeyLogin(t, dec, phone)
	require.NoError(t, err)
	require.Equal(t, service.LoginAuthenticated, res.Outcome)
	require.Equal(t, domain.MfaMethodPasskey, res.Method)
	require.True(t, res.Session.MFAVerified)
	require.Equal(t, "passkey", res.Session.MFAMethodType)

	stored, err := f.methods.GetByID(ctx, m.ID)
	require.NoError(t, err)
	require.Contains(t, stored.WebAuthnCredential, `"signCount":1`, "sign counter persisted")
	require.False(t, stored.LastUsedAt.IsZero())

	// 3. A passkey-only client accepts this session, amr says "hwk".
	a, err := f.core.IssueIdentityAssertion(ctx, res.Session.ID, mfaClientPasskey, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"pwd", "hwk", "mfa"}, a.AuthMethods)

	// 4. Codes cannot answer with a passkey method name, and vice versa.
	dec = f.beginLogin(t, aliceID, "")
	_, err = f.verify(dec, "passkey", "123456")
	require.ErrorIs(t, err, service.ErrMFAMethodNotAllowed)
}

func TestMFA_PasskeyAttacks(t *testing.T) {
	ctx := context.Background()

	t.Run("a signed answer cannot be replayed", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)

		dec := f.beginLogin(t, aliceID, "")
		options, err := f.mfa.BeginPasskeyLogin(ctx, realmA, dec.ChallengeToken)
		require.NoError(t, err)
		response, err := phone.Get(options)
		require.NoError(t, err)
		_, err = f.mfa.FinishPasskeyLogin(ctx, service.VerifyPasskeyLoginInput{RealmID: realmA, ChallengeToken: dec.ChallengeToken, Response: response})
		require.NoError(t, err)

		dec = f.beginLogin(t, aliceID, "")
		_, err = f.mfa.BeginPasskeyLogin(ctx, realmA, dec.ChallengeToken)
		require.NoError(t, err)
		_, err = f.mfa.FinishPasskeyLogin(ctx, service.VerifyPasskeyLoginInput{RealmID: realmA, ChallengeToken: dec.ChallengeToken, Response: response})
		var codeErr *service.MFACodeError
		require.ErrorAs(t, err, &codeErr, "old challenge inside the signed data")
		require.Equal(t, domain.LoginFailureMfaFailed, f.attempts.last().FailureReason)

		// The ceremony is single use: answering again needs new options.
		_, err = f.mfa.FinishPasskeyLogin(ctx, service.VerifyPasskeyLoginInput{RealmID: realmA, ChallengeToken: dec.ChallengeToken, Response: response})
		require.ErrorIs(t, err, service.ErrWebAuthnCeremonyInvalid)
	})

	t.Run("phishing site", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		phone.SetOrigin("https://sso.test.evil.example")
		dec := f.beginLogin(t, aliceID, "")
		_, err := f.passkeyLogin(t, dec, phone)
		var codeErr *service.MFACodeError
		require.ErrorAs(t, err, &codeErr)
	})

	t.Run("cloned authenticator is refused and audited", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
		for i := 0; i < 2; i++ {
			_, err := f.passkeyLogin(t, f.beginLogin(t, aliceID, ""), phone)
			require.NoError(t, err)
		}
		phone.SetSignCount(0)
		_, err := f.passkeyLogin(t, f.beginLogin(t, aliceID, ""), phone)
		var codeErr *service.MFACodeError
		require.ErrorAs(t, err, &codeErr)
		last := f.audit.entries[len(f.audit.entries)-1]
		require.Equal(t, "mfa_passkey_clone_warning", last.Action)
		require.Equal(t, domain.AuditLogCritical, last.Level)
	})

	t.Run("registration ceremony belongs to its session", func(t *testing.T) {
		f := newMFAFixture(t)
		phone := passkeytest.New(testOrigin)
		sess := f.passwordSession(t, aliceID)
		options, err := f.mfa.BeginPasskeyRegistration(ctx, f.user(aliceID), sess, service.PasskeyKindPasskey, "")
		require.NoError(t, err)
		response, err := phone.Create(options)
		require.NoError(t, err)

		other := f.passwordSession(t, aliceID)
		_, err = f.mfa.FinishPasskeyRegistration(ctx, f.user(aliceID), other, response)
		require.ErrorIs(t, err, service.ErrWebAuthnCeremonyInvalid, "another session cannot finish it")

		_, err = f.mfa.FinishPasskeyRegistration(ctx, f.user(aliceID), sess, response)
		require.NoError(t, err)
		_, err = f.mfa.FinishPasskeyRegistration(ctx, f.user(aliceID), sess, response)
		require.ErrorIs(t, err, service.ErrWebAuthnCeremonyInvalid, "single use")
	})

	t.Run("bad kind", func(t *testing.T) {
		f := newMFAFixture(t)
		_, err := f.mfa.BeginPasskeyRegistration(ctx, f.user(aliceID), f.passwordSession(t, aliceID), "fingerprint", "")
		require.ErrorIs(t, err, service.ErrUnknownPasskeyKind)
	})
}

func TestMFA_SecurityKeyAndStepUp(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)
	yubikey := passkeytest.New(testOrigin)
	yubikey.Discoverable, yubikey.BackupEligible, yubikey.UserVerification = false, false, false

	m, _, _ := f.enrollPasskey(t, aliceID, yubikey, service.PasskeyKindSecurityKey)
	require.Equal(t, domain.MfaMethodWebAuthn, m.Type, "a non-discoverable credential is a security key")
	require.False(t, m.IsDiscoverable)

	// A phone passkey as a second device: no new backup codes.
	phone := passkeytest.New(testOrigin)
	_, codes, _ := f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
	require.Empty(t, codes)
	require.Equal(t, 2, len(mustList(t, f, aliceID).Methods))

	// Login: both credentials are allowed, the YubiKey answers.
	dec := f.beginLogin(t, aliceID, "")
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodWebAuthn, domain.MfaMethodBackupCodes}, dec.Methods)
	res, err := f.passkeyLogin(t, dec, yubikey)
	require.NoError(t, err)
	require.Equal(t, domain.MfaMethodWebAuthn, res.Method)

	// The YubiKey does not satisfy a passkey-only client.
	_, err = f.core.IssueIdentityAssertion(ctx, res.Session.ID, mfaClientPasskey, nil)
	require.Error(t, err)

	// Step-up with the phone passkey fixes it, on the same session.
	options, err := f.mfa.BeginPasskeyStepUp(ctx, res.Session)
	require.NoError(t, err)
	response, err := phone.Get(options)
	require.NoError(t, err)
	upd, method, err := f.mfa.FinishPasskeyStepUp(ctx, res.Session, response, "", "")
	require.NoError(t, err)
	require.Equal(t, domain.MfaMethodPasskey, method)
	require.Equal(t, res.Session.ID, upd.ID)
	_, err = f.core.IssueIdentityAssertion(ctx, upd.ID, mfaClientPasskey, nil)
	require.NoError(t, err)

	// A login restricted to passkeys does not offer the YubiKey.
	dec = f.beginLogin(t, aliceID, mfaClientPasskey)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey}, dec.Methods)
	options, err = f.mfa.BeginPasskeyLogin(ctx, realmA, dec.ChallengeToken)
	require.NoError(t, err)
	_, err = yubikey.Get(options)
	require.Error(t, err, "the YubiKey's credential is not in allowCredentials")
}

func TestMFA_PasskeysDisabled(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)
	phone := passkeytest.New(testOrigin)
	f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)

	// Same data, server restarted without WEBAUTHN_RP_ID.
	noPasskeys := service.NewMFAService(service.MFADeps{
		Users: f.users, Methods: f.methods, BackupCodes: f.codes, Sessions: f.sessionSvc, Policy: f.policy,
		Envelope: service.NewEnvelopeService(f.keys, localdev.New("test"), "local_dev"),
		Store:    mfastore.NewMemory(f.clock), Now: f.clock,
	})
	require.False(t, noPasskeys.PasskeysEnabled())
	_, err := noPasskeys.BeginPasskeyRegistration(ctx, f.user(aliceID), f.passwordSession(t, aliceID), service.PasskeyKindPasskey, "")
	require.ErrorIs(t, err, service.ErrPasskeysDisabled)

	dec, err := noPasskeys.BeginLogin(ctx, service.BeginLoginInput{User: f.user(aliceID)})
	require.NoError(t, err)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodBackupCodes}, dec.Methods,
		"passkeys cannot be verified, backup codes still work")

	// No backup code left: the login is refused, MFA is never skipped.
	_, err = f.codes.DeleteByUser(ctx, aliceID)
	require.NoError(t, err)
	_, err = noPasskeys.BeginLogin(ctx, service.BeginLoginInput{User: f.user(aliceID)})
	require.ErrorIs(t, err, service.ErrMFAUnavailable)
}

func mustList(t *testing.T, f *mfaFixture, userID string) *service.FactorList {
	t.Helper()
	l, err := f.mfa.ListFactors(context.Background(), userID)
	require.NoError(t, err)
	return l
}
