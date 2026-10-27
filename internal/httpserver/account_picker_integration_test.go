package httpserver_test

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	samllib "github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/ent/knownaccount"
	entuser "sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
)

// Step 18b: "Pick an account", one signed-in account per browser, the
// sign-out confirmation of RP-initiated logout, and the audit of sign-outs.

var (
	reContinueToken = regexp.MustCompile(`data-continue-token="([^"]*)"`)
	reRequestID     = regexp.MustCompile(`data-request-id="([^"]*)"`)
	reForgetAccount = regexp.MustCompile(`class="link forget" data-account="([^"]*)"`)
	reLogoutID      = regexp.MustCompile(`name="id" value="([^"]*)"`)
	reLogoutToken   = regexp.MustCompile(`name="logout_token" value="([^"]*)"`)
)

func submatch(t *testing.T, re *regexp.Regexp, body string) string {
	t.Helper()
	m := re.FindStringSubmatch(body)
	require.NotNil(t, m, "%s not found in: %.400s", re, body)
	return html.UnescapeString(m[1])
}

// signInKept runs a sign-in with "Keep me signed in" (or not) for web, and
// returns the id_token (the application keeps it for the logout).
func (e *oidcTestEnv) signInKept(t *testing.T, b *oidcBrowser, cfg *oauth2.Config, user string, remember bool) string {
	t.Helper()
	verifier := oauth2.GenerateVerifier()
	resp := b.get(cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(verifier)))
	loginURL := resp.Request.URL.String()
	status, body := b.postJSON(e.realmURL+"/auth/login", map[string]any{
		"identifier": user, "password": oidcPassword, "client_id": cfg.ClientID, "remember_me": remember})
	require.Equal(t, http.StatusOK, status, "%v", body)
	code := codeFromRedirect(t, b.get(loginURL), cfg.RedirectURL, "s")
	tok, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
	require.NoError(t, err)
	return tok.Extra("id_token").(string)
}

func (e *oidcTestEnv) logoutURL(idToken, state string) string {
	return e.disc.EndSessionEndpoint + "?" + url.Values{
		"id_token_hint": {idToken}, "post_logout_redirect_uri": {webLogoutURI}, "state": {state},
	}.Encode()
}

// browserSession is the id of the browser's current session.
func (e *oidcTestEnv) browserSession(t *testing.T, b *oidcBrowser) string {
	t.Helper()
	resp, err := b.c.Get(e.realmURL + "/auth/session")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out["session_id"].(string)
}

func (e *oidcTestEnv) sessionRow(t *testing.T, id string) *ent.Session {
	t.Helper()
	s, err := e.ent.Session.Get(context.Background(), id)
	require.NoError(t, err)
	return s
}

func (e *oidcTestEnv) logouts(t *testing.T, sessionID string) []*ent.AuditLog {
	t.Helper()
	rows, err := e.ent.AuditLog.Query().
		Where(auditlog.Action("logout"), auditlog.ResourceID(sessionID)).All(context.Background())
	require.NoError(t, err)
	return rows
}

func TestOIDC_Integration_AccountPicker(t *testing.T) {
	e := setupOIDCTestEnv(t)
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)
	pkce := func() oauth2.AuthCodeOption { return oauth2.S256ChallengeOption(oauth2.GenerateVerifier()) }
	selectAccount := oauth2.SetAuthURLParam("prompt", "select_account")

	t.Run("kept signed in: the account stays in the picker after a logout", func(t *testing.T) {
		b := e.newBrowser(t)
		idToken := e.signInKept(t, b, web, "alice", true)
		sid := e.browserSession(t, b)

		resp := b.get(e.logoutURL(idToken, "bye"))
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.True(t, strings.HasPrefix(resp.Header.Get("Location"), webLogoutURI+"?state=bye"), resp.Header.Get("Location"))
		require.Equal(t, "revoked", string(e.sessionRow(t, sid).Status), "same browser: signed out without a question")
		logs := e.logouts(t, sid)
		require.Len(t, logs, 1)
		require.Equal(t, map[string]interface{}{"via": "oidc", "remember_me": true, "client_id": webClientID}, logs[0].Details)

		resp, body := b.page(web.AuthCodeURL("s", pkce()))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, body, `data-mode="pick"`)
		require.Contains(t, body, `data-identifier="alice@acme.test"`)
		require.Contains(t, body, "Signed out")
		require.Contains(t, body, ">Forget<")
	})

	t.Run("not kept: nothing remembered", func(t *testing.T) {
		b := e.newBrowser(t)
		idToken := e.signInKept(t, b, web, "alice", false)
		b.get(e.logoutURL(idToken, "bye"))
		_, body := b.page(web.AuthCodeURL("s", pkce()))
		require.Contains(t, body, `data-mode="login"`)
		require.NotContains(t, body, `class="account"`)
	})

	t.Run("another browser sees nothing", func(t *testing.T) {
		e.signInKept(t, e.newBrowser(t), web, "alice", true)
		_, body := e.newBrowser(t).page(web.AuthCodeURL("s", pkce()))
		require.Contains(t, body, `data-mode="login"`)
	})

	t.Run("select_account: the signed-in tile goes on without a password", func(t *testing.T) {
		b := e.newBrowser(t)
		e.signInKept(t, b, web, "alice", true)
		resp, body := b.page(web.AuthCodeURL("s2", pkce(), selectAccount))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, body, `data-mode="pick"`)
		require.Contains(t, body, "Signed in")
		require.Contains(t, body, ">Sign out and forget<")
		loginURL := resp.Request.URL.String()
		id, token := submatch(t, reRequestID, body), submatch(t, reContinueToken, body)

		status, _ := b.postJSON(e.realmURL+"/oidc/login/continue", map[string]string{"id": id, "token": "forged"})
		require.Equal(t, http.StatusBadRequest, status)
		status, _ = b.postJSON(e.realmURL+"/oidc/login/continue", map[string]string{"id": id, "token": token})
		require.Equal(t, http.StatusNoContent, status)
		codeFromRedirect(t, b.get(loginURL), webRedirectURI, "s2")

		status, _ = b.postJSON(e.realmURL+"/oidc/login/continue", map[string]string{"id": id, "token": token})
		require.Equal(t, http.StatusBadRequest, status, "the token works once")
	})

	t.Run("select_account without a session: the remembered accounts", func(t *testing.T) {
		b := e.newBrowser(t)
		idToken := e.signInKept(t, b, web, "alice", true)
		b.get(e.logoutURL(idToken, "bye"))
		_, body := b.page(web.AuthCodeURL("s", pkce(), selectAccount))
		require.Contains(t, body, `data-mode="pick"`)
		require.NotContains(t, body, "Signed in")
		require.Contains(t, body, `data-continue-token=""`, "nothing to go on with")
	})

	t.Run("prompt=login: the current account pre-filled", func(t *testing.T) {
		b := e.newBrowser(t)
		e.signInKept(t, b, web, "alice", true)
		_, body := b.page(web.AuthCodeURL("s", pkce(), oauth2.SetAuthURLParam("prompt", "login")))
		require.Contains(t, body, `data-mode="login"`)
		require.Contains(t, body, `value="alice@acme.test"`)
	})

	t.Run("another account signing in ends the previous session", func(t *testing.T) {
		b := e.newBrowser(t)
		e.signInKept(t, b, web, "alice", true)
		aliceSID := e.browserSession(t, b)

		status, body := b.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "bob", "password": oidcPassword})
		require.Equal(t, http.StatusOK, status, "%v", body)
		row := e.sessionRow(t, aliceSID)
		require.Equal(t, "revoked", string(row.Status))
		require.Equal(t, string(domain.SessionRevokedAccountSwitch), row.RevokedReason)
		logs := e.logouts(t, aliceSID)
		require.Len(t, logs, 1)
		require.Equal(t, "account_switch", logs[0].Details["via"])
	})

	t.Run("the same account signing in again keeps its previous session", func(t *testing.T) {
		b := e.newBrowser(t)
		e.signInKept(t, b, web, "alice", true)
		first := e.browserSession(t, b)
		status, _ := b.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "alice", "password": oidcPassword})
		require.Equal(t, http.StatusOK, status)
		require.NotEqual(t, first, e.browserSession(t, b))
		require.Equal(t, "active", string(e.sessionRow(t, first).Status))
	})

	t.Run("Sign out and forget", func(t *testing.T) {
		b := e.newBrowser(t)
		e.signInKept(t, b, web, "alice", true)
		sid := e.browserSession(t, b)
		_, body := b.page(web.AuthCodeURL("s", pkce(), selectAccount))
		accountID := submatch(t, reForgetAccount, body)

		status, _ := e.newBrowser(t).postJSON(e.realmURL+"/auth/accounts/forget", map[string]string{"account_id": accountID})
		require.Equal(t, http.StatusNotFound, status, "another browser cannot forget it")

		status, _ = b.postJSON(e.realmURL+"/auth/accounts/forget", map[string]string{"account_id": accountID})
		require.Equal(t, http.StatusNoContent, status)
		require.Equal(t, "revoked", string(e.sessionRow(t, sid).Status), "the signed-in account is signed out too")
		require.Equal(t, "forget", e.logouts(t, sid)[0].Details["via"])
		n, err := e.ent.KnownAccount.Query().Where(knownaccount.ID(accountID)).Count(context.Background())
		require.NoError(t, err)
		require.Zero(t, n)
		forgets, err := e.ent.AuditLog.Query().Where(auditlog.Action("known_account.forget")).Count(context.Background())
		require.NoError(t, err)
		require.Equal(t, 1, forgets)

		_, body = b.page(web.AuthCodeURL("s", pkce()))
		require.Contains(t, body, `data-mode="login"`, "no session, no tile")

		status, _ = b.postJSON(e.realmURL+"/auth/accounts/forget", map[string]string{"account_id": accountID})
		require.Equal(t, http.StatusNotFound, status, "already gone")
	})

	t.Run("a deleted account disappears with its tiles", func(t *testing.T) {
		ctx := context.Background()
		bob, err := e.ent.User.Query().Where(entuser.Username("bob")).Only(ctx)
		require.NoError(t, err)
		b := e.newBrowser(t)
		status, _ := b.postJSON(e.realmURL+"/auth/login", map[string]any{"identifier": "bob", "password": oidcPassword, "remember_me": true})
		require.Equal(t, http.StatusOK, status)
		n, err := e.ent.KnownAccount.Query().Where(knownaccount.UserID(bob.ID)).Count(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.NoError(t, e.ent.User.DeleteOneID(bob.ID).Exec(ctx))
		n, err = e.ent.KnownAccount.Query().Where(knownaccount.UserID(bob.ID)).Count(ctx)
		require.NoError(t, err)
		require.Zero(t, n, "ON DELETE CASCADE")
	})
}

func TestOIDC_Integration_LogoutConfirmation(t *testing.T) {
	e := setupOIDCTestEnv(t)
	web := e.oauth(webClientID, e.webSecret, webRedirectURI)

	// confirmPage opens the logout link in a browser that is not alice's.
	confirmPage := func(t *testing.T, b *oidcBrowser, idToken string) (string, string) {
		t.Helper()
		resp, body := b.page(e.logoutURL(idToken, "bye"))
		require.Equal(t, http.StatusOK, resp.StatusCode, body)
		require.Contains(t, body, "Sign out of Acme Corp?")
		require.Contains(t, body, "alice@acme.test")
		require.Contains(t, body, "Web App")
		require.NotContains(t, resp.Header.Get("Content-Security-Policy"), "form-action",
			"the answer redirects to the application: no form-action rule")
		return submatch(t, reLogoutID, body), submatch(t, reLogoutToken, body)
	}
	answer := func(b *oidcBrowser, id, token, decision string) *http.Response {
		resp, err := b.c.PostForm(e.realmURL+"/oidc/logout/confirm",
			url.Values{"id": {id}, "logout_token": {token}, "decision": {decision}})
		require.NoError(t, err)
		resp.Body.Close()
		return resp
	}

	alice := e.newBrowser(t)
	idToken := e.signInKept(t, alice, web, "alice", true)
	sid := e.browserSession(t, alice)
	other := e.newBrowser(t)

	t.Run("Cancel keeps the session and goes back to the application", func(t *testing.T) {
		id, token := confirmPage(t, other, idToken)
		resp := answer(other, id, token, "cancel")
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, webLogoutURI+"?state=bye", resp.Header.Get("Location"))
		require.Equal(t, "active", string(e.sessionRow(t, sid).Status))
		require.Empty(t, e.logouts(t, sid))
	})

	t.Run("a forged token shows the page again", func(t *testing.T) {
		id, _ := confirmPage(t, other, idToken)
		resp := answer(other, id, "forged", "signout")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "/r/"+oidcRealm+"/oidc/logout/confirm", resp.Request.URL.Path, "redirected to the page")
		require.Equal(t, "active", string(e.sessionRow(t, sid).Status))
	})

	t.Run("only the browser that opened the page can answer", func(t *testing.T) {
		id, token := confirmPage(t, other, idToken)
		resp := answer(e.newBrowser(t), id, token, "signout")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "active", string(e.sessionRow(t, sid).Status))
	})

	t.Run("Sign out ends the session, audited as confirmed", func(t *testing.T) {
		id, token := confirmPage(t, other, idToken)
		resp := answer(other, id, token, "signout")
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		require.Equal(t, webLogoutURI+"?state=bye", resp.Header.Get("Location"))
		require.Equal(t, "revoked", string(e.sessionRow(t, sid).Status))
		logs := e.logouts(t, sid)
		require.Len(t, logs, 1)
		require.Equal(t, true, logs[0].Details["confirmed"])

		resp = answer(other, id, token, "signout")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "single use")
	})

	t.Run("a session already over: straight back, no question", func(t *testing.T) {
		resp := other.get(e.logoutURL(idToken, "again"))
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.Equal(t, webLogoutURI+"?state=again", resp.Header.Get("Location"))
	})
}

func TestSAMLIntegration_AccountPicker(t *testing.T) {
	env := setupSAMLTestEnv(t)
	wiki := env.newSP(t, spOpts{name: "wiki", signed: true, slo: true, allow: true})
	ctx := context.Background()

	b := env.browser(t)
	body := `{"identifier":"alice","password":"` + samlPassword + `","remember_me":true}`
	req, _ := http.NewRequest(http.MethodPost, env.realmURL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := b.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	t.Run("ForceAuthn: the current account pre-filled", func(t *testing.T) {
		u, _ := wiki.redirectRequest(func(r *samllib.AuthnRequest) { force := true; r.ForceAuthn = &force })
		_, page := b.get(u)
		require.Contains(t, page, `data-mode="login"`)
		require.Contains(t, page, `value="alice@acme.test"`)
	})

	t.Run("signed out: the picker", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, env.realmURL+"/auth/logout", nil)
		resp, _ := b.do(req)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		n, err := env.ent.AuditLog.Query().Where(auditlog.Action("logout")).All(ctx)
		require.NoError(t, err)
		require.Len(t, n, 1)
		require.Equal(t, "auth_api", n[0].Details["via"])

		u, _ := wiki.redirectRequest(nil)
		_, page := b.get(u)
		require.Contains(t, page, `data-mode="pick"`)
		require.Contains(t, page, `data-identifier="alice@acme.test"`)
	})
}

func TestSAMLSingleLogout_IsAudited(t *testing.T) {
	env := setupSAMLTestEnv(t)
	wiki := env.newSP(t, spOpts{name: "wiki", signed: true, slo: true, allow: true})
	b := env.browser(t)
	u, reqID := wiki.redirectRequest(nil)
	_, fields := b.signIn(func() (*http.Response, string) { return b.get(u) }, "alice")
	a, err := wiki.assertion(fields["SAMLResponse"], reqID)
	require.NoError(t, err)

	lu, _ := wiki.logoutRequest(a.Subject.NameID.Value, domain.NameIDFormatPersistent, a.AuthnStatements[0].SessionIndex)
	resp, _ := b.get(lu)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	logs, err := env.ent.AuditLog.Query().Where(auditlog.Action("logout")).All(context.Background())
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.Equal(t, "saml_slo", logs[0].Details["via"])
	require.Equal(t, wiki.sp.EntityID, logs[0].Details["client_id"])
	require.Equal(t, sessionOf(t, env, a), logs[0].ResourceID)
}
