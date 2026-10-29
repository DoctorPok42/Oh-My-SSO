package httpserver_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/internal/passkey/passkeytest"
)

// Step 18e: the tile starts with the method last chosen on this device.

func TestOIDC_Integration_SignInMemory(t *testing.T) {
	e := setupOIDCTestEnv(t)
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)

	// alice: kept signed in on browser b, adds a passkey, signs out.
	b := e.newBrowser(t)
	phone := passkeytest.New(passkeyTestOrigin)
	idToken := e.signInKept(t, b, web, "alice", true)
	e.registerPasskey(t, b, phone, "passkey")
	b.get(e.logoutURL(idToken, "bye"))

	tileOf := func(t *testing.T) (account, methods string) {
		t.Helper()
		_, body := b.page(web.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
		m := reTileMethods.FindStringSubmatch(body)
		require.NotNil(t, m, "%.600s", body)
		return m[1], m[2]
	}
	password := func(t *testing.T, br *oidcBrowser, accountID string) {
		t.Helper()
		status, out := br.postJSON(e.realmURL+"/auth/login", map[string]any{
			"identifier": "alice", "password": oidcPassword, "client_id": webClientID, "remember_me": true, "account_id": accountID})
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, "mfa_required", out["status"], "the passkey is her second factor")
	}

	account, methods := tileOf(t)
	require.Equal(t, "passkey,password", methods, "the passkey first")

	t.Run("the id of this tile sent by another browser changes nothing", func(t *testing.T) {
		password(t, e.newBrowser(t), account)
		_, methods := tileOf(t)
		require.Equal(t, "passkey,password", methods)
	})
	t.Run("the password typed without the tile changes nothing", func(t *testing.T) {
		password(t, b, "")
		_, methods := tileOf(t)
		require.Equal(t, "passkey,password", methods)
	})
	t.Run("the password typed on the tile: the tile starts with it", func(t *testing.T) {
		password(t, b, account)
		_, methods := tileOf(t)
		require.Equal(t, "password,passkey", methods)
	})
	t.Run("a sign-in with the passkey: the passkey first again", func(t *testing.T) {
		status, out := e.passkeySignIn(t, b, phone, account)
		require.Equal(t, http.StatusOK, status, "%v", out)
		b.postJSON(e.realmURL+"/auth/logout", nil)
		_, methods := tileOf(t)
		require.Equal(t, "passkey,password", methods)
	})
}
