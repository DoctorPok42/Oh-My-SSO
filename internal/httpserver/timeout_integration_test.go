package httpserver_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent/loginattempt"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// Timeouts through the real HTTP stack: the sign-in page's answers, the
// OIDC errors, the refresh tokens, and the sign-out at the start.
func TestOIDC_Integration_Timeouts(t *testing.T) {
	e := setupOIDCTestEnv(t)
	ctx := context.Background()
	cli := service.TimeoutActor{By: "cli:test"}
	cfg := e.oauth(webClientID, e.webSecret, webRedirectURI, "offline_access")

	// The web client requires PKCE.
	authorize := func(b *oidcBrowser, state string) *http.Response {
		return b.get(cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	}
	signIn := func(b *oidcBrowser, password string) (int, map[string]any) {
		resp := authorize(b, "s-"+randomString(t))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, resp.Request.URL.Path, "/oidc/login", "a sign-in page is expected")
		return b.postJSON(e.realmURL+"/auth/login", map[string]any{
			"identifier": "alice", "password": password, "client_id": webClientID})
	}
	tokens := func(b *oidcBrowser) *oauth2.Token {
		verifier := oauth2.GenerateVerifier()
		code := e.loginAndGetCode(t, b, cfg, "alice", oauth2.S256ChallengeOption(verifier))
		tok, err := cfg.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		require.NoError(t, err)
		return tok
	}
	suspend := func(t *testing.T, typ domain.TimeoutTargetType, id string, starts time.Time) *service.TimeoutChange {
		c, err := e.timeouts.Create(ctx, service.CreateTimeoutInput{Realm: e.realm, TargetType: typ, TargetID: id,
			StartsAt: starts, Reason: "integration test", Actor: cli})
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = e.timeouts.Lift(ctx, e.realm, c.Timeout.ID, cli) })
		return c
	}
	lift := func(t *testing.T, c *service.TimeoutChange) {
		_, err := e.timeouts.Lift(ctx, e.realm, c.Timeout.ID, cli)
		require.NoError(t, err)
	}

	t.Run("a timeout on the client: its tokens stop, the application is unavailable", func(t *testing.T) {
		b := e.newBrowser(t)
		tok := tokens(b)

		c := suspend(t, domain.TimeoutTargetClientApp, e.web.ID, time.Time{})
		require.NotNil(t, c.SignOut)
		require.GreaterOrEqual(t, c.SignOut.Tokens, 2, "at least the access and the refresh token")

		_, err := e.refresh(cfg, tok.RefreshToken)
		requireInvalidGrant(t, err)
		status, _ := e.userinfo(t, tok.AccessToken)
		require.NotEqual(t, http.StatusOK, status, "the access token was revoked")

		// The SSO session is still there: the application gets an error.
		resp := authorize(b, "s1")
		require.Equal(t, "temporarily_unavailable", errorFromRedirect(t, resp, webRedirectURI))

		// A new browser: right password, the page says why.
		status, body := signIn(e.newBrowser(t), oidcPassword)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "client_unavailable", body["error"])

		lift(t, c)
		codeFromRedirect(t, authorize(b, "s2"), webRedirectURI, "s2")
	})

	t.Run("a timeout on the user signs them out and blocks the sign-in", func(t *testing.T) {
		b := e.newBrowser(t)
		tok := tokens(b)

		c := suspend(t, domain.TimeoutTargetUser, e.alice.ID, time.Time{})
		require.NotNil(t, c.SignOut)
		require.GreaterOrEqual(t, c.SignOut.Sessions, 1)

		_, err := e.refresh(cfg, tok.RefreshToken)
		requireInvalidGrant(t, err)

		status, body := signIn(b, oidcPassword) // the session is gone: the sign-in page
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "access_suspended", body["error"])

		status, body = signIn(e.newBrowser(t), "wrong password")
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "invalid_credentials", body["error"], "a wrong password never reveals the timeout")

		n, err := e.ent.LoginAttempt.Query().
			Where(loginattempt.UserID(e.alice.ID), loginattempt.FailureReason("timeout_active")).Count(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, n, 1)

		lift(t, c)
		tokens(e.newBrowser(t))
	})

	t.Run("a timeout on a group blocks its members", func(t *testing.T) {
		admins, err := entstore.NewGroupRepository(e.ent).GetByRealmAndName(ctx, e.realm.ID, "admins")
		require.NoError(t, err)
		c := suspend(t, domain.TimeoutTargetGroup, admins.ID, time.Time{})
		status, body := signIn(e.newBrowser(t), oidcPassword)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "access_suspended", body["error"])
		lift(t, c)
	})

	t.Run("a scheduled timeout: in force at its start, the enforcer signs out", func(t *testing.T) {
		t.Cleanup(e.clock.Reset)
		b := e.newBrowser(t)
		tok := tokens(b)

		c := suspend(t, domain.TimeoutTargetUser, e.alice.ID, e.clock.Now().Add(2*time.Minute))
		require.Nil(t, c.SignOut, "not started")
		next, err := e.refresh(cfg, tok.RefreshToken)
		require.NoError(t, err, "not started yet")

		e.clock.Advance(3 * time.Minute)
		_, err = e.refresh(cfg, next.RefreshToken)
		requireInvalidGrant(t, err) // the check blocks from the first second

		n, err := e.timeouts.EnforceDue(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		resp := authorize(b, "s3")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, resp.Request.URL.Path, "/oidc/login", "signed out: the sign-in page again")
	})
}
