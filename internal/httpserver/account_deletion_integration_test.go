package httpserver_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// "Delete my account" (GDPR article 17): only where the realm allows it,
// confirmed, signed out at once, kept by signing in again and cancelling,
// deleted for good once the delay is over.
func TestAccountConsole_Deletion_Integration(t *testing.T) {
	env := setupAccountTestEnv(t)
	ctx := context.Background()

	acme, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "acme", DisplayName: "Acme Corp"})
	require.NoError(t, err)
	beta, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "beta", DisplayName: "Beta Labs"})
	require.NoError(t, err)
	st, err := env.settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: acme.ID})
	require.NoError(t, err)
	on := true
	_, err = env.settings.Update(ctx, st.ID, repository.UpdateInstanceSettingsParams{AccountDeletionEnabled: &on})
	require.NoError(t, err)

	const pw = "correct-horse-battery-staple"
	hash, err := service.HashPassword(pw)
	require.NoError(t, err)
	alice, err := env.users.Create(ctx, repository.CreateUserParams{RealmID: acme.ID, Username: "alice",
		Email: "alice@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)
	_, err = env.users.Create(ctx, repository.CreateUserParams{RealmID: beta.ID, Username: "carol",
		Email: "carol@example.test", PasswordHash: hash, Status: domain.UserActive})
	require.NoError(t, err)

	// A realm that does not allow it: no form, and a forged request is refused.
	carol := env.newTab(t, "beta")
	carol.login("carol", pw)
	_, page := carol.get("/account/data")
	require.NotContains(t, page, "Delete my account")
	resp, _ := carol.post("/account/data/deletion", url.Values{"csrf": {csrfOf(t, page)}, "confirm": {"yes"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = carol.get("/account/data")
	require.Contains(t, page, "does not let you delete your account")

	b := env.newTab(t, "acme")
	b.login("alice", pw)
	_, page = b.get("/account/data")
	require.Contains(t, page, "Delete my account")
	csrf := csrfOf(t, page)

	resp, page = b.post("/account/data/deletion", url.Values{"csrf": {csrf}}, nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, "not confirmed")
	require.Contains(t, page, "Tick the box to confirm.")
	u, err := env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Nil(t, u.DeletionScheduledAt)

	resp, page = b.post("/account/data/deletion", url.Values{"csrf": {csrf}, "confirm": {"yes"}}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, page, "Your account will be deleted")
	u, err = env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.NotNil(t, u.DeletionScheduledAt)
	require.WithinDuration(t, env.clock.Now().Add(service.AccountDeletionDelay), *u.DeletionScheduledAt, time.Minute)
	status, _ := b.sessionID()
	require.Equal(t, http.StatusUnauthorized, status, "signed out at once")

	// Signing in again is possible (to keep the account), and every page
	// says what is going on.
	b.login("alice", pw)
	_, page = b.get("/account")
	require.Contains(t, page, "Your account will be deleted on")
	_, page = b.get("/account/data")
	require.Contains(t, page, "Keep my account")
	resp, _ = b.post("/account/data/deletion/cancel", url.Values{"csrf": {csrfOf(t, page)}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = b.get("/account/data")
	require.Contains(t, page, "Your account is kept")
	require.NotContains(t, page, "Your account will be deleted on")
	u, err = env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Nil(t, u.DeletionScheduledAt)
	_, page = b.get("/account/history?view=activity")
	require.Contains(t, page, "Deletion of your account requested")
	require.Contains(t, page, "Deletion of your account cancelled")

	// Asked again and kept to the end.
	_, page = b.get("/account/data")
	resp, _ = b.post("/account/data/deletion", url.Values{"csrf": {csrfOf(t, page)}, "confirm": {"yes"}}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	n, err := env.erasure.DeleteDue(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "not before its time")
	env.clock.Advance(service.AccountDeletionDelay + time.Hour)
	n, err = env.erasure.DeleteDue(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = env.users.GetByID(ctx, alice.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
	status, _ = b.api(http.MethodPost, "/auth/login", map[string]string{"identifier": "alice", "password": pw})
	require.NotEqual(t, http.StatusOK, status, "the account is gone")
}
