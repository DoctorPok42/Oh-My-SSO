package entstore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// What the account console (Step 14c) reads: a user's sign-in attempts,
// page by page, and the audit entries of a list of actions.
func TestAccountConsoleQueries(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)
	alice, err := users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "alice-acct", Email: "alice-acct@example.com"})
	require.NoError(t, err)
	bob, err := users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: "bob-acct", Email: "bob-acct@example.com"})
	require.NoError(t, err)

	attempts := entstore.NewLoginAttemptRepository(client)
	add := func(userID, ip string, status domain.LoginAttemptStatus) {
		_, err := attempts.Create(ctx, repository.CreateLoginAttemptParams{
			RealmID: realm.ID, UserID: userID, Identifier: "x", IPAddress: ip, Status: status,
		})
		require.NoError(t, err)
	}
	add(alice.ID, "192.0.2.1", domain.LoginAttemptFailure)
	add(alice.ID, "192.0.2.2", domain.LoginAttemptSuccess)
	add(bob.ID, "198.51.100.1", domain.LoginAttemptSuccess)
	add(alice.ID, "192.0.2.3", domain.LoginAttemptSuccess)

	page1, err := attempts.ListByUser(ctx, alice.ID, repository.Page{Offset: 0, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page1, 2)
	require.Equal(t, "192.0.2.3", page1[0].IPAddress, "newest first")
	require.Equal(t, "192.0.2.2", page1[1].IPAddress)
	page2, err := attempts.ListByUser(ctx, alice.ID, repository.Page{Offset: 2, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page2, 1)
	require.Equal(t, "192.0.2.1", page2[0].IPAddress)
	require.Equal(t, domain.LoginAttemptFailure, page2[0].Status)
	for _, a := range append(page1, page2...) {
		require.Equal(t, alice.ID, a.UserID, "only alice's attempts")
	}

	audit := entstore.NewAuditLogRepository(client)
	for _, action := range []string{"account.profile_updated", "admin.realm.update", "mfa_method_enrolled"} {
		_, err := audit.Create(ctx, repository.CreateAuditLogParams{
			RealmID: realm.ID, UserID: alice.ID, Action: action, ResourceType: "User", ResourceID: alice.ID,
			Level: domain.AuditLogInfo, Status: domain.AuditLogSuccess,
		})
		require.NoError(t, err)
	}
	admin := entstore.NewAdminRepository(client)
	rows, total, err := admin.SearchAuditLogs(ctx, repository.AuditSearch{
		RealmID: realm.ID, UserID: alice.ID,
		Actions: []string{"account.profile_updated", "mfa_method_enrolled"},
		Page:    repository.Page{Limit: 10},
	})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	got := []string{rows[0].Action, rows[1].Action}
	require.ElementsMatch(t, []string{"account.profile_updated", "mfa_method_enrolled"}, got)
}
