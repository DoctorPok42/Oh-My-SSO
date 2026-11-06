package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/passkey/passkeytest"
)

func methodsOf(m ...core.SignInMethod) service.SignInMethodsFunc {
	return func(context.Context, *domain.User) []core.SignInMethod { return m }
}

func (f *knownFixture) tile(t *testing.T, device string, methods service.SignInMethodsFunc) core.Account {
	t.Helper()
	out, err := f.accounts.ListWithMethods(context.Background(), core.AccountQuery{RealmID: realmA, DeviceID: device}, methods)
	require.NoError(t, err)
	require.Len(t, out, 1)
	return out[0]
}

func TestSignInMemory_Tile(t *testing.T) {
	ctx := context.Background()
	both := methodsOf(core.SignInPasskey, core.SignInPassword)
	pwFirst := []core.SignInMethod{core.SignInPassword, core.SignInPasskey}
	pkFirst := []core.SignInMethod{core.SignInPasskey, core.SignInPassword}

	setup := func(t *testing.T) (*knownFixture, core.Account) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		acc := f.tile(t, deviceA, both)
		require.Equal(t, pkFirst, acc.Methods, "by default the passkey first")
		return f, acc
	}
	chose := func(f *knownFixture, device, accountID, userID string, offered ...core.SignInMethod) {
		f.accounts.PasswordChosen(ctx, service.PasswordChosenInput{RealmID: realmA, DeviceID: device, AccountID: accountID, UserID: userID, Offered: offered})
	}

	t.Run("the signed-in account has its methods too: signing in again starts with the passkey", func(t *testing.T) {
		f := newKnownFixture()
		current := f.signIn(aliceID, deviceA, false) // not remembered: no tile row
		out, err := f.accounts.ListWithMethods(ctx, core.AccountQuery{RealmID: realmA, DeviceID: deviceA, Current: current}, both)
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.True(t, out[0].SignedIn)
		require.Equal(t, pkFirst, out[0].Methods)

		f, acc := setup(t) // remembered, and the password was chosen on its tile
		chose(f, deviceA, acc.ID, aliceID, core.SignInPasskey, core.SignInPassword)
		out, err = f.accounts.ListWithMethods(ctx, core.AccountQuery{RealmID: realmA, DeviceID: deviceA,
			Current: &domain.Session{ID: "s", RealmID: realmA, UserID: aliceID}}, both)
		require.NoError(t, err)
		require.Equal(t, pwFirst, out[0].Methods, "the choice made on this device still counts")
	})

	t.Run("the password typed on the tile comes first next time, the passkey brings itself back", func(t *testing.T) {
		f, acc := setup(t)
		chose(f, deviceA, acc.ID, aliceID, core.SignInPasskey, core.SignInPassword)
		require.Equal(t, pwFirst, f.tile(t, deviceA, both).Methods)

		f.accounts.PasskeySignIn(ctx, realmA, service.DeviceFingerprint(deviceA), aliceID)
		require.Equal(t, pkFirst, f.tile(t, deviceA, both).Methods)
	})
	t.Run("not a choice: the tile offered only the password", func(t *testing.T) {
		f, acc := setup(t)
		chose(f, deviceA, acc.ID, aliceID, core.SignInPassword)
		require.Equal(t, pkFirst, f.tile(t, deviceA, both).Methods, "a passkey added later comes first")
	})
	t.Run("the tile of another device, or of another account, changes nothing", func(t *testing.T) {
		f, acc := setup(t)
		chose(f, deviceB, acc.ID, aliceID, core.SignInPasskey, core.SignInPassword)
		chose(f, deviceA, acc.ID, bobID, core.SignInPasskey, core.SignInPassword)
		chose(f, deviceA, "", aliceID, core.SignInPasskey, core.SignInPassword)
		require.Equal(t, pkFirst, f.tile(t, deviceA, both).Methods)
	})
	t.Run("an application without passkeys: the password only, whatever was chosen", func(t *testing.T) {
		f, acc := setup(t)
		f.accounts.PasskeySignIn(ctx, realmA, service.DeviceFingerprint(deviceA), aliceID)
		chose(f, deviceA, acc.ID, aliceID, core.SignInPasskey, core.SignInPassword)
		require.Equal(t, []core.SignInMethod{core.SignInPassword}, f.tile(t, deviceA, methodsOf(core.SignInPassword)).Methods)
	})
	t.Run("a device that does not remember the account: nothing to record", func(t *testing.T) {
		f, _ := setup(t)
		f.accounts.PasskeySignIn(ctx, realmA, service.DeviceFingerprint(deviceB), aliceID)
		_, err := f.repo.Find(ctx, realmA, service.DeviceFingerprint(deviceB), aliceID)
		require.Error(t, err)
	})
}

// secondFactors: alice has a passkey and an authenticator app, and the
// laptop remembers her account.
type secondFactors struct {
	*mfaFixture
	phone  *passkeytest.Authenticator
	secret string
	codes  []string // backup codes
	laptop string   // DeviceFingerprint of the laptop
}

func secondFactorSetup(t *testing.T) secondFactors {
	t.Helper()
	f := newMFAFixture(t)
	phone := passkeytest.New(testOrigin)
	_, codes, _ := f.enrollPasskey(t, aliceID, phone, service.PasskeyKindPasskey)
	secret, _ := f.enrollTOTP(t, aliceID)
	laptop := service.DeviceFingerprint(deviceA)
	_, err := f.known.Touch(context.Background(), realmA, laptop, aliceID, f.now)
	require.NoError(t, err)
	return secondFactors{mfaFixture: f, phone: phone, secret: secret, codes: codes, laptop: laptop}
}

func (f *mfaFixture) totpLogin(t *testing.T, dec *service.LoginDecision, secret string) {
	t.Helper()
	_, err := f.mfa.VerifyLogin(context.Background(), service.VerifyLoginInput{
		RealmID: realmA, ChallengeToken: dec.ChallengeToken, Method: "totp", Code: totpAt(t, secret, f.now),
	})
	require.NoError(t, err)
	f.advance(30 * time.Second)
}

// A password typed on a tile must not lock the account into "password, then
// passkey": the passkey that answers the second step could have signed in alone.
func TestSignInMemory_PasswordThenSecondFactor(t *testing.T) {
	ctx := context.Background()
	password, passkey := string(core.SignInPassword), string(core.SignInPasskey)
	chosePassword := func(t *testing.T, f *mfaFixture, device string) {
		t.Helper()
		row, err := f.known.Find(ctx, realmA, service.DeviceFingerprint(device), aliceID)
		require.NoError(t, err)
		f.accounts.PasswordChosen(ctx, service.PasswordChosenInput{RealmID: realmA, DeviceID: device, AccountID: row.ID, UserID: aliceID,
			Offered: []core.SignInMethod{core.SignInPasskey, core.SignInPassword}})
	}
	lastMethod := func(t *testing.T, f *mfaFixture, device string) string {
		t.Helper()
		row, err := f.known.Find(ctx, realmA, service.DeviceFingerprint(device), aliceID)
		require.NoError(t, err)
		return row.LastMethod
	}

	t.Run("the passkey as second factor: the tile starts with the passkey again", func(t *testing.T) {
		f := secondFactorSetup(t)
		chosePassword(t, f.mfaFixture, deviceA)
		require.Equal(t, password, lastMethod(t, f.mfaFixture, deviceA))
		_, err := f.passkeyLogin(t, f.beginOn(t, aliceID, "", f.laptop), f.phone)
		require.NoError(t, err)
		require.Equal(t, passkey, lastMethod(t, f.mfaFixture, deviceA))
	})
	t.Run("an application that accepts only the passkey: the same", func(t *testing.T) {
		f := secondFactorSetup(t)
		chosePassword(t, f.mfaFixture, deviceA)
		_, err := f.passkeyLogin(t, f.beginOn(t, aliceID, mfaClientPasskey, f.laptop), f.phone)
		require.NoError(t, err)
		require.Equal(t, passkey, lastMethod(t, f.mfaFixture, deviceA))
	})
	t.Run("the authenticator app as second factor: the password stays the choice", func(t *testing.T) {
		f := secondFactorSetup(t)
		chosePassword(t, f.mfaFixture, deviceA)
		f.totpLogin(t, f.beginOn(t, aliceID, "", f.laptop), f.secret)
		require.Equal(t, password, lastMethod(t, f.mfaFixture, deviceA))
	})
	t.Run("a security key as second factor: the password stays, the key may not sign in alone", func(t *testing.T) {
		f := newMFAFixture(t)
		yubikey := passkeytest.New(testOrigin)
		f.enrollPasskey(t, aliceID, yubikey, service.PasskeyKindSecurityKey)
		laptop := service.DeviceFingerprint(deviceA)
		_, err := f.known.Touch(ctx, realmA, laptop, aliceID, f.now)
		require.NoError(t, err)
		chosePassword(t, f, deviceA)
		_, err = f.passkeyLogin(t, f.beginOn(t, aliceID, "", laptop), yubikey)
		require.NoError(t, err)
		require.Equal(t, password, lastMethod(t, f, deviceA))
	})
	t.Run("a device that does not remember the account: nothing to record", func(t *testing.T) {
		f := secondFactorSetup(t)
		other := service.DeviceFingerprint(deviceB)
		_, err := f.passkeyLogin(t, f.beginOn(t, aliceID, "", other), f.phone)
		require.NoError(t, err)
		_, err = f.known.Find(ctx, realmA, other, aliceID)
		require.Error(t, err)
	})
}

func TestSignInMemory_SecondFactor(t *testing.T) {
	ctx := context.Background()
	passkeyFirst := []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodTOTP, domain.MfaMethodBackupCodes}
	appFirst := []domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodPasskey, domain.MfaMethodBackupCodes}

	t.Run("the app chosen comes first on this device, the passkey brings itself back", func(t *testing.T) {
		f := secondFactorSetup(t)
		dec := f.beginOn(t, aliceID, "", f.laptop)
		require.Equal(t, passkeyFirst, dec.Methods, "by default the passkey first")
		f.totpLogin(t, dec, f.secret)

		dec = f.beginOn(t, aliceID, "", f.laptop)
		require.Equal(t, appFirst, dec.Methods)
		require.Equal(t, passkeyFirst, f.beginOn(t, aliceID, "", service.DeviceFingerprint(deviceB)).Methods, "another device")

		_, err := f.passkeyLogin(t, dec, f.phone)
		require.NoError(t, err)
		require.Equal(t, passkeyFirst, f.beginOn(t, aliceID, "", f.laptop).Methods)
	})
	t.Run("a backup code is never remembered", func(t *testing.T) {
		f := secondFactorSetup(t)
		f.totpLogin(t, f.beginOn(t, aliceID, "", f.laptop), f.secret)
		dec := f.beginOn(t, aliceID, "", f.laptop)
		_, err := f.mfa.VerifyLogin(ctx, service.VerifyLoginInput{RealmID: realmA, ChallengeToken: dec.ChallengeToken, Method: "backup_codes", Code: f.codes[0]})
		require.NoError(t, err)
		require.Equal(t, appFirst, f.beginOn(t, aliceID, "", f.laptop).Methods, "still the app")
	})
	t.Run("no choice: an application that accepts only the passkey", func(t *testing.T) {
		f := secondFactorSetup(t)
		f.totpLogin(t, f.beginOn(t, aliceID, "", f.laptop), f.secret)
		dec := f.beginOn(t, aliceID, mfaClientPasskey, f.laptop)
		require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey}, dec.Methods)
		_, err := f.passkeyLogin(t, dec, f.phone)
		require.NoError(t, err)
		require.Equal(t, appFirst, f.beginOn(t, aliceID, "", f.laptop).Methods, "that passkey was not a choice")
	})
	t.Run("Confirm it's you follows the same order", func(t *testing.T) {
		f := secondFactorSetup(t)
		sess := &domain.Session{ID: "s", RealmID: realmA, UserID: aliceID, DeviceFingerprint: f.laptop}
		st, err := f.mfa.Status(ctx, sess, nil)
		require.NoError(t, err)
		require.Equal(t, passkeyFirst, st.EnrolledMethods)
		f.totpLogin(t, f.beginOn(t, aliceID, "", f.laptop), f.secret)
		st, err = f.mfa.Status(ctx, sess, nil)
		require.NoError(t, err)
		require.Equal(t, appFirst, st.EnrolledMethods)
	})
	t.Run("a device that does not remember the account keeps the default", func(t *testing.T) {
		f := secondFactorSetup(t)
		other := service.DeviceFingerprint(deviceB)
		f.totpLogin(t, f.beginOn(t, aliceID, "", other), f.secret)
		require.Equal(t, passkeyFirst, f.beginOn(t, aliceID, "", other).Methods)
	})
}
