package httpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/passkey/passkeytest"
)

func TestOIDC_Integration_TrustedDevice(t *testing.T) {
	e := setupOIDCTestEnv(t)
	ctx := context.Background()
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)

	// alice: kept signed in on browser b, a passkey as her first factor.
	b := e.newBrowser(t)
	phone := passkeytest.New(passkeyTestOrigin)
	e.signInKept(t, b, web, "alice", true)
	e.registerPasskey(t, b, phone, "passkey")
	b.postJSON(e.realmURL+"/auth/logout", nil)

	login := func(b *oidcBrowser, clientID string) map[string]any {
		t.Helper()
		status, out := b.postJSON(e.realmURL+"/auth/login", map[string]any{
			"identifier": "alice", "password": oidcPassword, "client_id": clientID, "remember_me": true})
		require.Equal(t, http.StatusOK, status, "%v", out)
		return out
	}
	secondFactor := func(b *oidcBrowser, trust bool) map[string]any {
		t.Helper()
		status, opts := b.postJSON(e.realmURL+"/auth/mfa/webauthn/options", map[string]any{})
		require.Equal(t, http.StatusOK, status, "%v", opts)
		cred, err := phone.Get(rawJSON(t, opts))
		require.NoError(t, err)
		status, out := b.postJSON(e.realmURL+"/auth/mfa/webauthn/verify", map[string]any{"credential": json.RawMessage(cred), "trust_device": trust})
		require.Equal(t, http.StatusOK, status, "%v", out)
		return out
	}
	trustB := func() {
		t.Helper()
		out := login(b, webClientID)
		require.Equal(t, "mfa_required", out["status"])
		require.EqualValues(t, 30, out["trust_device_days"], "the box is offered, for 30 days")
		out = secondFactor(b, true)
		require.Equal(t, true, out["device_trusted"])
		b.postJSON(e.realmURL+"/auth/logout", nil)
	}
	trustB()

	t.Run("audited", func(t *testing.T) {
		n, err := e.ent.AuditLog.Query().Where(auditlog.Action("mfa_device_trusted"), auditlog.UserID(e.alice.ID)).Count(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n)
	})

	t.Run("the next sign-in on this browser: the password alone, amr pwd", func(t *testing.T) {
		verifier := oauth2.GenerateVerifier()
		resp := b.get(web.AuthCodeURL("s", oauth2.S256ChallengeOption(verifier)))
		loginURL := resp.Request.URL.String()
		out := login(b, webClientID)
		require.Equal(t, "authenticated", out["status"])
		require.Equal(t, true, out["trusted_device"])

		row := e.sessionRow(t, e.browserSession(t, b))
		require.True(t, row.TrustedDevice)
		require.False(t, row.MfaVerified)

		code := codeFromRedirect(t, b.get(loginURL), webRedirectURI, "s")
		tok, err := web.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		require.NoError(t, err)
		require.Equal(t, []any{"pwd"}, e.verifyJWT(t, tok.Extra("id_token").(string))["amr"], "no second factor was given")
		b.postJSON(e.realmURL+"/auth/logout", nil)
	})

	t.Run("another browser still asks", func(t *testing.T) {
		require.Equal(t, "mfa_required", login(e.newBrowser(t), webClientID)["status"])
	})

	t.Run("an application that requires MFA asks, without the box", func(t *testing.T) {
		out := login(b, payrollClientID)
		require.Equal(t, "mfa_required", out["status"])
		require.Nil(t, out["trust_device_days"])
		secondFactor(b, true) // ticked anyway: ignored
		b.postJSON(e.realmURL+"/auth/logout", nil)
		require.Equal(t, "authenticated", login(b, webClientID)["status"], "the first trust is still there")
		b.postJSON(e.realmURL+"/auth/logout", nil)
	})

	t.Run("Forget on the tile ends the trust", func(t *testing.T) {
		_, body := b.page(web.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
		account := submatch(t, reForgetAccount, body)
		status, out := b.postJSON(e.realmURL+"/auth/accounts/forget", map[string]string{"account_id": account})
		require.Equal(t, http.StatusNoContent, status, "%v", out)
		require.Equal(t, "mfa_required", login(b, webClientID)["status"])
	})

	t.Run("signed out everywhere ends the trust", func(t *testing.T) {
		secondFactor(b, true)
		b.postJSON(e.realmURL+"/auth/logout", nil)
		require.Equal(t, "authenticated", login(b, webClientID)["status"])
		require.NoError(t, e.sessions.RevokeAllForUser(ctx, e.alice.ID, domain.SessionRevokedAdminRevoked))
		require.Equal(t, "mfa_required", login(b, webClientID)["status"])
		n, err := e.ent.AuditLog.Query().Where(auditlog.Action("mfa_device_trust_revoked"), auditlog.UserID(e.alice.ID)).Count(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, n, "forget, then the revocation")
	})
}
