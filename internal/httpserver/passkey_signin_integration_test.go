package httpserver_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/passkey/passkeytest"
)

// from a tile of "Pick an account" or from "Try another way".
var reTileMethods = regexp.MustCompile(`data-account="([^"]+)" data-methods="([^"]*)"`)

// rawJSON turns a decoded JSON object back into bytes (the software
// authenticator reads the options as JSON).
func rawJSON(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// registerPasskey adds a passkey to the account signed in in b (right after
// its sign-in: a user without factor only needs a recent login).
func (e *oidcTestEnv) registerPasskey(t *testing.T, b *oidcBrowser, auth *passkeytest.Authenticator, kind string) {
	t.Helper()
	status, opts := b.postJSON(e.realmURL+"/account/mfa/webauthn/register/options", map[string]string{"kind": kind, "name": "Phone"})
	require.Equal(t, http.StatusOK, status, "%v", opts)
	cred, err := auth.Create(rawJSON(t, opts))
	require.NoError(t, err)
	status, out := b.postJSON(e.realmURL+"/account/mfa/webauthn/register/verify", json.RawMessage(cred))
	require.Equal(t, http.StatusOK, status, "%v", out)
}

// passkeySignIn runs POST /auth/passkey/options + verify; accountID "" is a
// discoverable passkey. It returns the status and body of verify.
func (e *oidcTestEnv) passkeySignIn(t *testing.T, b *oidcBrowser, auth *passkeytest.Authenticator, accountID string) (int, map[string]any) {
	t.Helper()
	body := map[string]string{"client_id": webClientID}
	if accountID != "" {
		body["account_id"] = accountID
	}
	status, opts := b.postJSON(e.realmURL+"/auth/passkey/options", body)
	if status != http.StatusOK {
		return status, opts
	}
	cred, err := auth.Get(rawJSON(t, opts))
	require.NoError(t, err)
	return b.postJSON(e.realmURL+"/auth/passkey/verify", map[string]any{"credential": json.RawMessage(cred), "remember_me": true})
}

func TestOIDC_Integration_PasskeySignIn(t *testing.T) {
	e := setupOIDCTestEnv(t)
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)

	// alice: kept signed in on browser b, adds a passkey, signs out. Her
	// tile stays on b.
	b := e.newBrowser(t)
	phone := passkeytest.New(passkeyTestOrigin)
	idToken := e.signInKept(t, b, web, "alice", true)
	e.registerPasskey(t, b, phone, "passkey")
	b.get(e.logoutURL(idToken, "bye"))

	type tile struct{ account, methods, loginURL, verifier string }
	tileOf := func(t *testing.T, b *oidcBrowser) tile {
		t.Helper()
		verifier := oauth2.GenerateVerifier()
		resp, body := b.page(web.AuthCodeURL("s", oauth2.S256ChallengeOption(verifier)))
		require.Contains(t, body, `data-mode="pick"`)
		m := reTileMethods.FindStringSubmatch(body)
		require.NotNil(t, m, "%.600s", body)
		return tile{account: m[1], methods: m[2], loginURL: resp.Request.URL.String(), verifier: verifier}
	}

	t.Run("the tile starts with the passkey", func(t *testing.T) {
		tl := tileOf(t, b)
		require.NotEmpty(t, tl.account)
		require.Equal(t, "passkey,password", tl.methods)
	})

	t.Run("tile click: the passkey alone signs in, amr hwk + mfa", func(t *testing.T) {
		tl := tileOf(t, b)
		status, out := e.passkeySignIn(t, b, phone, tl.account)
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, "authenticated", out["status"])
		require.Equal(t, "passkey", out["mfa_method"])

		code := codeFromRedirect(t, b.get(tl.loginURL), webRedirectURI, "s")
		tok, err := web.Exchange(e.ctx(), code, oauth2.VerifierOption(tl.verifier))
		require.NoError(t, err)
		claims := e.verifyJWT(t, tok.Extra("id_token").(string))
		require.Equal(t, []any{"hwk", "mfa"}, claims["amr"])
		b.get(e.logoutURL(tok.Extra("id_token").(string), "bye"))
	})

	t.Run("Try another way: any passkey of the browser, no tile", func(t *testing.T) {
		other := e.newBrowser(t)
		_, body := other.page(web.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
		require.Contains(t, body, `data-mode="login"`)
		require.Contains(t, body, `data-passkeys="on"`)
		require.Contains(t, body, `id="try-another"`)
		status, out := e.passkeySignIn(t, other, phone, "")
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, e.alice.ID, out["user_id"])
	})

	t.Run("a tile of another device cannot be used", func(t *testing.T) {
		status, out := e.passkeySignIn(t, e.newBrowser(t), phone, tileOf(t, b).account)
		require.Equal(t, http.StatusNotFound, status, "%v", out)
	})

	t.Run("the ceremony belongs to the browser that asked for it", func(t *testing.T) {
		status, opts := b.postJSON(e.realmURL+"/auth/passkey/options", map[string]string{"client_id": webClientID})
		require.Equal(t, http.StatusOK, status)
		cred, err := phone.Get(rawJSON(t, opts))
		require.NoError(t, err)
		status, out := e.newBrowser(t).postJSON(e.realmURL+"/auth/passkey/verify", map[string]any{"credential": json.RawMessage(cred)})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "webauthn_ceremony_expired", out["error"])
	})

	t.Run("locked out by wrong passwords: the passkey still signs in", func(t *testing.T) {
		attacker := e.newBrowser(t)
		for i := 0; i < 5; i++ {
			attacker.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "alice", "password": "wrong", "client_id": webClientID})
		}
		status, out := attacker.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "alice", "password": oidcPassword, "client_id": webClientID})
		require.Equal(t, http.StatusTooManyRequests, status, "the password is locked: %v", out)

		status, out = e.passkeySignIn(t, b, phone, tileOf(t, b).account)
		require.Equal(t, http.StatusOK, status, "%v", out)
		b.postJSON(e.realmURL+"/auth/logout", nil)
	})

	t.Run("a suspended account cannot sign in", func(t *testing.T) {
		account := tileOf(t, b).account
		require.NoError(t, e.ent.User.UpdateOneID(e.alice.ID).SetStatus(schema.UserSuspended).Exec(e.ctx()))
		t.Cleanup(func() { _ = e.ent.User.UpdateOneID(e.alice.ID).SetStatus(schema.UserActive).Exec(e.ctx()) })

		status, out := e.passkeySignIn(t, b, phone, account)
		require.Equal(t, http.StatusConflict, status, "the tile offers nothing: %v", out)
		require.Equal(t, "passkey_unavailable", out["error"])
		status, out = e.passkeySignIn(t, e.newBrowser(t), phone, "")
		require.Equal(t, http.StatusUnauthorized, status, "%v", out)
		require.Equal(t, "passkey_rejected", out["error"])
	})
}
