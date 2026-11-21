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

// "Change your e-mail address": only where the realm allows it; the address
// only changes once the link e-mailed to the new one is used, and the
// previous address is told.
func TestAccountConsole_EmailChange_Integration(t *testing.T) {
	env := setupAccountTestEnv(t)
	ctx := context.Background()

	acme, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "acme", DisplayName: "Acme Corp"})
	require.NoError(t, err)
	beta, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "beta", DisplayName: "Beta Labs"})
	require.NoError(t, err)
	st, err := env.settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: acme.ID})
	require.NoError(t, err)
	on := true
	_, err = env.settings.Update(ctx, st.ID, repository.UpdateInstanceSettingsParams{EmailChangeAllowed: &on})
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
	newUser(acme.ID, "bob")
	newUser(beta.ID, "carol")

	// A realm that does not allow it (the default): no form, and a forged
	// request is refused.
	carol := env.newTab(t, "beta")
	carol.login("carol", pw)
	_, page := carol.get("/account")
	require.NotContains(t, page, "Change your e-mail address")
	require.Contains(t, page, "To change your username or e-mail address, ask your administrator.")
	resp, _ := carol.post("/account/profile/email", url.Values{"csrf": {csrfOf(t, page)}, "new_email": {"carol@new.example"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = carol.get("/account")
	require.Contains(t, page, "does not let you change your e-mail address")
	require.Empty(t, env.mails.kinds(domain.NotificationEmailVerification))

	b := env.newTab(t, "acme")
	b.login("alice", pw)
	_, page = b.get("/account")
	require.Contains(t, page, "Change your e-mail address")
	csrf := csrfOf(t, page)

	resp, page = b.post("/account/profile/email", url.Values{"csrf": {csrf}, "new_email": {"bob@example.test"}}, nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	require.Contains(t, page, "Another account already uses this address.")

	resp, _ = b.post("/account/profile/email", url.Values{"csrf": {csrf}, "new_email": {"Alice.New@Example.test"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = b.get("/account")
	require.Contains(t, page, "We sent a confirmation link to your new address.")
	require.Contains(t, page, "alice.new@example.test")
	u, err := env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Equal(t, "alice@example.test", u.Email, "applications keep the old address until it is confirmed")
	require.Equal(t, "alice.new@example.test", u.PendingEmail)

	links := env.mails.kinds(domain.NotificationEmailVerification)
	require.Len(t, links, 1)
	require.Equal(t, "alice.new@example.test", links[0].To)

	// The link of the e-mail (its page calls Verify).
	u, err = env.verify.Verify(ctx, acme.ID, links[0].ResetToken, "203.0.113.9", "test")
	require.NoError(t, err)
	require.Equal(t, "alice.new@example.test", u.Email)
	require.NotNil(t, u.EmailVerifiedAt)
	require.Empty(t, u.PendingEmail)
	told := env.mails.kinds(domain.NotificationEmailChanged)
	require.Len(t, told, 1)
	require.Equal(t, "alice@example.test", told[0].To)

	_, page = b.get("/account/history?view=activity")
	require.Contains(t, page, "Change of e-mail address requested")
	require.Contains(t, page, "E-mail address changed")

	// Asked again, then cancelled: the address stays.
	env.clock.Advance(time.Minute)
	_, page = b.get("/account")
	resp, _ = b.post("/account/profile/email", url.Values{"csrf": {csrfOf(t, page)}, "new_email": {"alice@other.example"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	// Again within the minute: the answer is next to the field, focused
	// (the card is low on the page).
	resp, page = b.post("/account/profile/email", url.Values{"csrf": {csrfOf(t, page)}, "new_email": {"alice@typo.example"}}, nil)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	require.Contains(t, page, "less than a minute ago")
	require.Contains(t, page, `aria-invalid="true" aria-describedby="new-email-error" autofocus`)
	_, page = b.get("/account")
	require.Contains(t, page, "Cancel the change")
	resp, _ = b.post("/account/profile/email/cancel", url.Values{"csrf": {csrfOf(t, page)}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_, page = b.get("/account")
	require.Contains(t, page, "The change of address is cancelled")
	u, err = env.users.GetByID(ctx, alice.ID)
	require.NoError(t, err)
	require.Equal(t, "alice.new@example.test", u.Email)
	require.Empty(t, u.PendingEmail)

	// An old sign-in: "Confirm it's you" first (a stolen session must not
	// move the account to another mailbox), and no link meanwhile.
	env.clock.Advance(5 * time.Minute)
	_, page = b.get("/account")
	env.clock.Advance(6 * time.Minute)
	links = env.mails.kinds(domain.NotificationEmailVerification)
	resp, _ = b.post("/account/profile/email", url.Values{"csrf": {csrfOf(t, page)}, "new_email": {"alice@third.example"}}, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, "/r/acme/account/profile/email", resp.Header.Get("Location"))
	require.Len(t, env.mails.kinds(domain.NotificationEmailVerification), len(links), "no link before confirming it's you")
	_, page = b.get("/account/profile/email")
	require.Contains(t, page, "enter your password again")
}
