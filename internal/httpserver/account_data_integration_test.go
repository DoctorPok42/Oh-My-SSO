package httpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// "Your data": ask for a copy, download it once made, only after a recent
// "Confirm it's you", and only one's own.
func TestAccountConsole_DataExport_Integration(t *testing.T) {
	env := setupAccountTestEnv(t)
	ctx := context.Background()

	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "acme", DisplayName: "Acme Corp"})
	require.NoError(t, err)
	const pw = "correct-horse-battery-staple"
	hash, err := service.HashPassword(pw)
	require.NoError(t, err)
	for _, name := range []string{"alice", "bob"} {
		_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: name,
			Email: name + "@example.test", PasswordHash: hash, Status: domain.UserActive})
		require.NoError(t, err)
	}

	b := env.newTab(t, "acme")
	b.login("alice", pw)
	_, page := b.get("/account")
	require.Contains(t, page, `href="/r/acme/account/data"`, "the tab")

	resp, page := b.get("/account/data")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "Ask for a copy")
	require.NotContains(t, page, "/data/download")
	csrf := csrfOf(t, page)

	resp, _ = b.post("/account/data/export", url.Values{}, nil)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "no CSRF token")
	resp, _ = b.post("/account/data/export", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "/r/acme/account/data", resp.Header.Get("Location"))

	// Made in the background.
	require.Eventually(t, func() bool {
		_, page = b.get("/account/data")
		return strings.Contains(page, "/data/download")
	}, 10*time.Second, 50*time.Millisecond)
	require.Contains(t, page, "Your copy is ready")
	// No "download" attribute: a refused download (confirmation expired,
	// copy gone) must lead back to this page, not save it as a file.
	require.Contains(t, page, `href="/r/acme/account/data/download">`)

	resp, body := b.get("/account/data/download")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	require.Contains(t, resp.Header.Get("Content-Disposition"), "attachment")
	require.Contains(t, resp.Header.Get("Content-Disposition"), `filename=acme-data-`)
	var doc struct {
		Account struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"account"`
		Sessions []map[string]any `json:"sessions"`
		SignIns  []map[string]any `json:"sign_ins"`
		Activity []struct {
			Action string `json:"action"`
		} `json:"activity"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &doc))
	require.Equal(t, "alice", doc.Account.Username)
	require.Equal(t, "alice@example.test", doc.Account.Email)
	require.Len(t, doc.Sessions, 1)
	require.NotEmpty(t, doc.SignIns)
	require.NotContains(t, body, hash, "no password hash")
	actions := []string{}
	for _, a := range doc.Activity {
		actions = append(actions, a.Action)
	}
	require.Contains(t, actions, "user.data_export_requested")

	_, page = b.get("/account/history?view=activity")
	require.Contains(t, page, "Copy of your data downloaded", "the user sees it in the account's activity")

	// Someone else's session never gets it.
	bob := env.newTab(t, "acme")
	bob.login("bob", pw)
	resp, _ = bob.get("/account/data/download")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = bob.get("/account/data")
	require.Contains(t, page, "There is no copy to download any more.")
	require.NotContains(t, page, "/data/download")

	// An old sign-in: confirm it's you first.
	env.clock.Advance(5 * time.Minute)
	_, _ = b.get("/account")
	env.clock.Advance(6 * time.Minute)
	resp, _ = b.get("/account/data/download")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "/r/acme/account/data", resp.Header.Get("Location"))
	resp, page = b.get("/account/data")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, `data-mode="login"`)
	require.Contains(t, page, "to get a copy of your data")
	resp, _ = b.post("/account/data/export", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "/r/acme/account/data", resp.Header.Get("Location"), "sent back to confirm first")
}
