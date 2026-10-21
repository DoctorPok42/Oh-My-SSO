package httpserver_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 13 Definition of Done, end to end through the OIDC login page: the
// consent screen is shown once for the same scopes, again when a new scope
// appears, never for a client without require_consent (unless it sends
// prompt=consent), and a revocation ends the client's access.

var reConsentAction = regexp.MustCompile(`<form method="post" action="([^"]*)">`)

// consentForm reads the consent page: where it posts, and its hidden fields
// (request id and one-time token).
func consentForm(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	require.Contains(t, body, `name="consent_token"`, "consent page expected, got: %.300s", body)
	m := reConsentAction.FindStringSubmatch(body)
	require.NotNil(t, m)
	form := url.Values{}
	for _, f := range reField.FindAllStringSubmatch(body, -1) {
		form.Set(f[1], html.UnescapeString(f[2]))
	}
	return html.UnescapeString(m[1]), form
}

func (b *oidcBrowser) postForm(u string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.c.PostForm(u, form)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

// answer posts the consent page with decision=allow|deny.
func (e *oidcTestEnv) answer(t *testing.T, b *oidcBrowser, page, decision string) *http.Response {
	t.Helper()
	action, form := consentForm(t, page)
	form.Set("decision", decision)
	resp, _ := b.postForm(e.ts.URL+action, form)
	return resp
}

func TestOIDC_Integration_Consent(t *testing.T) {
	e := setupOIDCTestEnv(t)
	ctx := context.Background()
	partner := e.oauth(partnerClientID, e.partnerSecret, partnerRedirectURI, "profile", "email", "offline_access")
	pkce := func() oauth2.AuthCodeOption { return oauth2.S256ChallengeOption(oauth2.GenerateVerifier()) }
	promptConsent := oauth2.SetAuthURLParam("prompt", "consent")
	app, err := entstore.NewClientRepository(e.ent).GetByRealmAndClientID(ctx, e.realm.ID, partnerClientID)
	require.NoError(t, err)
	stored := func(t *testing.T) *domain.Consent {
		t.Helper()
		c, err := entstore.NewConsentRepository(e.ent).GetByUserAndClient(ctx, e.alice.ID, app.ID)
		require.NoError(t, err)
		return c
	}
	// AuditLog.user_id is who acted: alice for her answers, the admin (here
	// "test", no user id) for a revocation.
	audited := func(t *testing.T, action string) int {
		t.Helper()
		n, err := e.ent.AuditLog.Query().Where(auditlog.Action(action)).Count(ctx)
		require.NoError(t, err)
		return n
	}

	// One browser, one password: the Step 4 rate limit counts logins.
	b := e.newBrowser(t)
	var first *oauth2.Token

	t.Run("first use: the consent page, Allow, then the code", func(t *testing.T) {
		verifier := oauth2.GenerateVerifier()
		resp := b.get(partner.AuthCodeURL("c1", oauth2.S256ChallengeOption(verifier)))
		loginURL := resp.Request.URL.String()
		status, out := b.postJSON(e.realmURL+"/auth/login", map[string]any{
			"identifier": "alice", "password": oidcPassword, "client_id": partnerClientID})
		require.Equal(t, http.StatusOK, status, "%v", out)

		resp, page := b.page(loginURL) // what login.js does: reload
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, page, "Allow Partner Portal to access your account?")
		require.Contains(t, page, "Signed in as <strong>alice</strong>")
		for _, item := range []string{"Who you are", "Your profile", "Your e-mail address", "Stay signed in"} {
			require.Contains(t, page, item)
		}
		require.Contains(t, page, "partner.example.test", "where the user goes next")
		require.NotContains(t, page, `class="tag"`, "first use: nothing is marked new")
		require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		require.Contains(t, resp.Header.Get("Content-Security-Policy"), "form-action 'self'")

		code := codeFromRedirect(t, e.answer(t, b, page, "allow"), partnerRedirectURI, "c1")
		tok, err := partner.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		require.NoError(t, err)
		require.NotEmpty(t, tok.RefreshToken)
		first = tok

		c := stored(t)
		require.Equal(t, domain.ConsentGranted, c.Status)
		require.ElementsMatch(t, []string{"profile", "email", "offline_access"}, c.Scopes)
		require.Equal(t, 1, audited(t, "consent_granted"))
	})

	t.Run("the same scopes again: no page", func(t *testing.T) {
		codeFromRedirect(t, b.get(partner.AuthCodeURL("c2", pkce())), partnerRedirectURI, "c2")
	})

	t.Run("a new scope: asked again, the new one marked, merged into the same row", func(t *testing.T) {
		more := e.oauth(partnerClientID, e.partnerSecret, partnerRedirectURI, "profile", "email", "offline_access", "groups")
		resp, page := b.page(more.AuthCodeURL("c3", pkce()))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, page, "It now asks for more than before")
		require.Contains(t, page, `groups <em class="tag">new</em>`)
		codeFromRedirect(t, e.answer(t, b, page, "allow"), partnerRedirectURI, "c3")

		require.ElementsMatch(t, []string{"profile", "email", "offline_access", "groups"}, stored(t).Scopes)
		n, err := e.ent.Consent.Query().Count(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n, "one row per user and client")
	})

	t.Run("a forged, foreign or stale form grants nothing", func(t *testing.T) {
		_, page := b.page(partner.AuthCodeURL("c4", pkce(), promptConsent))
		action, form := consentForm(t, page)
		form.Set("decision", "allow")

		other := e.newBrowser(t) // without the browser binding cookie
		resp, _ := other.postForm(e.ts.URL+action, form)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		forged := url.Values{}
		for k, v := range form {
			forged[k] = v
		}
		forged.Set("consent_token", "forged")
		resp, again := b.postForm(e.ts.URL+action, forged)
		require.Equal(t, http.StatusOK, resp.StatusCode, "back to a fresh consent page")
		_, fresh := consentForm(t, again)
		require.NotEqual(t, form.Get("consent_token"), fresh.Get("consent_token"))

		resp, again = b.postForm(e.ts.URL+action, form) // the first token was replaced
		require.Equal(t, http.StatusOK, resp.StatusCode)
		codeFromRedirect(t, e.answer(t, b, again, "allow"), partnerRedirectURI, "c4")
	})

	t.Run("prompt=consent on a client without require_consent: once, on demand", func(t *testing.T) {
		web := e.oauth(webClientID, e.webSecret, webRedirectURI, "profile")
		_, page := b.page(web.AuthCodeURL("w1", pkce(), promptConsent))
		require.Contains(t, page, "Allow Web App to access your account?")
		codeFromRedirect(t, e.answer(t, b, page, "allow"), webRedirectURI, "w1")
		codeFromRedirect(t, b.get(web.AuthCodeURL("w2", pkce())), webRedirectURI, "w2")
	})

	t.Run("revoked: tokens and pending codes stop working, the page comes back, Deny", func(t *testing.T) {
		verifier := oauth2.GenerateVerifier()
		code := codeFromRedirect(t, b.get(partner.AuthCodeURL("r0", oauth2.S256ChallengeOption(verifier))), partnerRedirectURI, "r0")

		res, err := e.consent.Revoke(ctx, service.RevokeConsentInput{RealmID: e.realm.ID, UserID: e.alice.ID,
			ClientRef: app.ID, Actor: service.PolicyActor{TriggeredBy: "test"}})
		require.NoError(t, err)
		require.Positive(t, res.TokensRevoked)

		_, err = partner.Exchange(e.ctx(), code, oauth2.VerifierOption(verifier))
		requireInvalidGrant(t, err) // re-checked at the code exchange
		_, err = e.refresh(partner, first.RefreshToken)
		requireInvalidGrant(t, err)
		status, _ := e.userinfo(t, first.AccessToken)
		require.NotEqual(t, http.StatusOK, status)

		require.Equal(t, "consent_required",
			errorFromRedirect(t, b.get(partner.AuthCodeURL("r1", pkce(), oauth2.SetAuthURLParam("prompt", "none"))), partnerRedirectURI))

		_, page := b.page(partner.AuthCodeURL("r2", pkce()))
		require.NotContains(t, page, "more than before", "after a revocation it is a first use again")
		require.Equal(t, "access_denied", errorFromRedirect(t, e.answer(t, b, page, "deny"), partnerRedirectURI))
		require.Equal(t, domain.ConsentRevoked, stored(t).Status, "a refusal stores nothing")
		require.Equal(t, 1, audited(t, "consent_denied"))
		require.Equal(t, 1, audited(t, "consent_revoked"))
	})

	t.Run("require_consent off: never asked", func(t *testing.T) {
		_, err := e.consent.SetClientRequirement(ctx, service.SetClientConsentInput{RealmID: e.realm.ID,
			ClientRef: app.ID, Required: false, Actor: service.PolicyActor{TriggeredBy: "test"}})
		require.NoError(t, err)
		resp := b.get(partner.AuthCodeURL("off", pkce()))
		require.False(t, strings.Contains(resp.Request.URL.Path, "/consent"))
		codeFromRedirect(t, resp, partnerRedirectURI, "off")
	})
}
