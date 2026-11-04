package httpserver_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// The "Language" card of the account console: the account's language, the
// browser's, and the same language for the person's accounts of the other
// organizations signed in on this browser.
func TestAccountConsole_Language_Integration(t *testing.T) {
	env := setupAccountTestEnv(t)
	ctx := context.Background()

	acme, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "acme", DisplayName: "Acme Corp"})
	require.NoError(t, err)
	beta, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "beta", DisplayName: "Beta Labs"})
	require.NoError(t, err)
	const pw = "correct-horse-battery-staple"
	hash, err := service.HashPassword(pw)
	require.NoError(t, err)
	newUser := func(realmID, name string) *domain.User {
		u, err := env.users.Create(ctx, repository.CreateUserParams{RealmID: realmID, Username: name,
			Email: name + "@example.test", PasswordHash: hash, Status: domain.UserActive})
		require.NoError(t, err)
		return u
	}
	alice := newUser(acme.ID, "alice")
	aliceAtBeta := newUser(beta.ID, "alice") // the same person, in another organization
	dave := newUser(beta.ID, "dave")

	laptop := env.newTab(t, "acme")

	// --- English by default -----------------------------------------------------
	resp, page := laptop.get("/account")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `<html lang="en">`)
	require.Equal(t, "en", resp.Header.Get("Content-Language"))
	require.Contains(t, page, ">Sign in</h1>")

	laptop.login("alice", pw)
	status, body := laptop.api(http.MethodPost, "/r/beta/auth/login", map[string]string{"identifier": "alice", "password": pw})
	require.Equal(t, http.StatusOK, status, string(body))

	_, page = laptop.get("/account")
	require.Contains(t, page, `id="language-form"`)
	require.Contains(t, page, `<option value="en" lang="en" selected>English</option>`)
	require.Contains(t, page, `<option value="fr" lang="fr">Français</option>`)
	csrf := csrfOf(t, page)

	// --- a language that does not exist ------------------------------------------
	resp, _ = laptop.post("/account/language", url.Values{"csrf": {csrf}, "locale": {"xx"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = laptop.get("/account")
	require.Contains(t, page, "This language is not available.")

	// --- French ---------------------------------------------------------------------
	resp, _ = laptop.post("/account/language", url.Values{"csrf": {csrf}, "locale": {"fr"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "fr", laptop.cookie("/", "omsso_locale"), "the browser's language too")
	u, err := env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Equal(t, "fr", u.Profile["locale"], "the account's language (the OIDC locale claim)")

	resp, page = laptop.get("/account")
	require.Equal(t, "fr", resp.Header.Get("Content-Language"))
	require.Contains(t, page, `<html lang="fr">`)
	require.Contains(t, page, "Votre langue a été enregistrée.")
	require.Contains(t, page, `<option value="fr" lang="fr" selected>Français</option>`)
	require.Contains(t, page, `data-locale-sync="/r/beta/account/language/sync"`, "account.js copies it to beta")
	require.Contains(t, page, `"account.js.codes.copied":"Copié"`, "the script's texts")

	// The next page does not ask again.
	_, page = laptop.get("/account")
	require.NotContains(t, page, "data-locale-sync")

	// --- the other organization of this browser ------------------------------------------
	resp, _ = laptop.post("/r/beta/account/language/sync", nil, http.Header{"Sec-Fetch-Site": {"cross-site"}})
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "another site cannot trigger it")
	resp, _ = laptop.post("/r/beta/account/language/sync", nil, http.Header{"Sec-Fetch-Site": {"same-origin"}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	u, err = env.users.GetByID(ctx, aliceAtBeta.ID)
	require.NoError(t, err)
	require.Equal(t, "fr", u.Profile["locale"], "alice's account at beta follows")
	_, page = laptop.get("/r/beta/account")
	require.Contains(t, page, `<html lang="fr">`)
	require.Contains(t, page, "Profil")

	// A browser not signed in to beta changes nothing there.
	stranger := env.newTab(t, "beta")
	resp, _ = stranger.post("/r/beta/account/language/sync", nil, nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	u, err = env.users.GetByID(ctx, dave.ID)
	require.NoError(t, err)
	require.Nil(t, u.Profile["locale"])

	// --- a new browser: English until the account signs in -----------------------------
	phone := env.newTab(t, "acme")
	_, page = phone.get("/account")
	require.Contains(t, page, `<html lang="en">`)
	phone.login("alice", pw)
	require.Equal(t, "fr", phone.cookie("/", "omsso_locale"), "the sign-in brings the account's language")
	_, page = phone.get("/account")
	require.Contains(t, page, `<html lang="fr">`)

	// --- the history says it --------------------------------------------------------------
	_, page = laptop.get("/account/history?view=activity")
	require.Contains(t, page, "Langue modifiée")
}
