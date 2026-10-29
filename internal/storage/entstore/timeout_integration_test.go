package entstore_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// The SQL of the timeout repository against PostgreSQL: the group
// membership subquery, the in-force predicate, the conditional updates.
func TestTimeoutRepository(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	users := entstore.NewUserRepository(client)
	groups := entstore.NewGroupRepository(client)
	admin := entstore.NewAdminRepository(client)
	repo := entstore.NewTimeoutRepository(client)

	newUser := func() string {
		name := "u-" + uuid.NewString()[:8]
		u, err := users.Create(ctx, repository.CreateUserParams{RealmID: realm.ID, Username: name, Email: name + "@example.com"})
		require.NoError(t, err)
		return u.ID
	}
	alice, bob, carol := newUser(), newUser(), newUser()
	staff, err := groups.Create(ctx, repository.CreateGroupParams{RealmID: realm.ID, Name: "staff-" + uuid.NewString()[:8]})
	require.NoError(t, err)
	require.NoError(t, admin.SetUserGroups(ctx, alice, []string{staff.ID}))
	require.NoError(t, admin.SetUserGroups(ctx, bob, []string{staff.ID}))
	app, err := entstore.NewClientRepository(client).Create(ctx, repository.CreateClientAppParams{
		RealmID: realm.ID, Name: "app", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)

	// Times are rounded: PostgreSQL keeps microseconds.
	now := time.Now().UTC().Truncate(time.Second)
	create := func(typ domain.TimeoutTargetType, id string, starts, ends time.Time) *domain.Timeout {
		to, err := repo.Create(ctx, repository.CreateTimeoutParams{RealmID: realm.ID, TargetType: typ, TargetID: id,
			StartsAt: starts, EndsAt: ends, Reason: "test", CreatedBy: "cli:test"})
		require.NoError(t, err)
		return to
	}
	ids := func(rows []*domain.Timeout) []string {
		out := []string{}
		for _, r := range rows {
			out = append(out, r.ID)
		}
		return out
	}

	onGroup := create(domain.TimeoutTargetGroup, staff.ID, now.Add(-time.Hour), time.Time{})
	onBob := create(domain.TimeoutTargetUser, bob, now.Add(-time.Hour), now.Add(time.Hour))
	onApp := create(domain.TimeoutTargetClientApp, app.ID, now.Add(-time.Minute), time.Time{})
	later := create(domain.TimeoutTargetUser, carol, now.Add(time.Hour), time.Time{})
	past := create(domain.TimeoutTargetUser, carol, now.Add(-2*time.Hour), now.Add(-time.Hour))

	t.Run("in force: through a group, directly, on the client", func(t *testing.T) {
		got, err := repo.InForce(ctx, alice, "", now)
		require.NoError(t, err)
		require.Equal(t, []string{onGroup.ID}, ids(got), "alice: her group")

		got, err = repo.InForce(ctx, bob, app.ID, now)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{onGroup.ID, onBob.ID, onApp.ID}, ids(got))

		got, err = repo.InForce(ctx, carol, "", now)
		require.NoError(t, err)
		require.Empty(t, got, "carol: one scheduled, one over")

		got, err = repo.InForce(ctx, carol, "", now.Add(90*time.Minute))
		require.NoError(t, err)
		require.Equal(t, []string{later.ID}, ids(got), "once started")

		got, err = repo.InForce(ctx, "", "", now)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("a new member of a suspended group is blocked at once", func(t *testing.T) {
		require.NoError(t, admin.SetUserGroups(ctx, carol, []string{staff.ID}))
		t.Cleanup(func() { require.NoError(t, admin.SetUserGroups(ctx, carol, nil)) })
		got, err := repo.InForce(ctx, carol, "", now)
		require.NoError(t, err)
		require.Equal(t, []string{onGroup.ID}, ids(got))
	})

	t.Run("members of a group", func(t *testing.T) {
		got, err := groups.ListMemberIDs(ctx, staff.ID)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{alice, bob}, got)
	})

	t.Run("list: current and past, paginated", func(t *testing.T) {
		cur, past2 := true, false
		rows, total, err := repo.ListByRealm(ctx, realm.ID, repository.TimeoutFilter{Current: &cur, At: now}, repository.Page{Limit: 10})
		require.NoError(t, err)
		require.Equal(t, 4, total)
		require.Equal(t, later.ID, rows[0].ID, "latest start first")

		rows, total, err = repo.ListByRealm(ctx, realm.ID, repository.TimeoutFilter{Current: &past2, At: now}, repository.Page{Limit: 10})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Equal(t, []string{past.ID}, ids(rows))

		rows, total, err = repo.ListByRealm(ctx, realm.ID, repository.TimeoutFilter{At: now}, repository.Page{Limit: 2, Offset: 2})
		require.NoError(t, err)
		require.Equal(t, 5, total)
		require.Len(t, rows, 2)
	})

	t.Run("update: reason, end, no end", func(t *testing.T) {
		reason, end := "new reason", now.Add(3*time.Hour)
		got, err := repo.Update(ctx, onBob.ID, repository.UpdateTimeoutParams{Reason: &reason, EndsAt: &end})
		require.NoError(t, err)
		require.Equal(t, reason, got.Reason)
		require.True(t, end.Equal(got.EndsAt))

		none := time.Time{}
		got, err = repo.Update(ctx, onBob.ID, repository.UpdateTimeoutParams{EndsAt: &none})
		require.NoError(t, err)
		require.True(t, got.EndsAt.IsZero())

		_, err = repo.Update(ctx, uuid.NewString(), repository.UpdateTimeoutParams{Reason: &reason})
		require.ErrorIs(t, err, repository.ErrNotFound)
		_, err = repo.GetByID(ctx, uuid.NewString())
		require.ErrorIs(t, err, repository.ErrNotFound)
	})

	t.Run("enforcement: listed once started, claimed once", func(t *testing.T) {
		due, err := repo.ListToEnforce(ctx, now, 50)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{onGroup.ID, onBob.ID, onApp.ID}, ids(due))

		// Two servers claim the same timeout at the same time: one wins.
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := repo.MarkEnforced(ctx, onApp.ID, now)
				require.NoError(t, err)
				if ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		require.Equal(t, int32(1), wins.Load())

		due, err = repo.ListToEnforce(ctx, now, 50)
		require.NoError(t, err)
		require.NotContains(t, ids(due), onApp.ID)

		require.NoError(t, repo.ClearEnforced(ctx, onApp.ID))
		due, err = repo.ListToEnforce(ctx, now, 50)
		require.NoError(t, err)
		require.Contains(t, ids(due), onApp.ID, "cleared: listed again")
	})

	t.Run("lift: once, then never in force again", func(t *testing.T) {
		at := now.Add(time.Minute)
		ok, err := repo.Lift(ctx, onGroup.ID, "user:admin", at)
		require.NoError(t, err)
		require.True(t, ok)
		ok, err = repo.Lift(ctx, onGroup.ID, "user:admin", at)
		require.NoError(t, err)
		require.False(t, ok, "already lifted")

		got, err := repo.GetByID(ctx, onGroup.ID)
		require.NoError(t, err)
		require.True(t, at.Equal(got.LiftedAt))
		require.True(t, at.Equal(got.EndsAt))
		require.Equal(t, "user:admin", got.LiftedBy)

		rows, err := repo.InForce(ctx, alice, "", at)
		require.NoError(t, err)
		require.Empty(t, rows)

		reason := "too late"
		_, err = repo.Update(ctx, onGroup.ID, repository.UpdateTimeoutParams{Reason: &reason})
		require.ErrorIs(t, err, repository.ErrNotFound, "a lifted timeout does not change")

		ok, err = repo.Lift(ctx, past.ID, "user:admin", at)
		require.NoError(t, err)
		require.False(t, ok, "an ended timeout is not lifted")

		// A scheduled one is cancelled: its end comes before its start.
		ok, err = repo.Lift(ctx, later.ID, "user:admin", at)
		require.NoError(t, err)
		require.True(t, ok)
		rows, err = repo.InForce(ctx, carol, "", now.Add(2*time.Hour))
		require.NoError(t, err)
		require.Empty(t, rows)
		due, err := repo.ListToEnforce(ctx, now.Add(2*time.Hour), 50)
		require.NoError(t, err)
		require.NotContains(t, ids(due), later.ID)
	})
}

func TestTokenRevokeByClient(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	realm := newTestRealm(t, ctx, client)
	u, err := entstore.NewUserRepository(client).Create(ctx, repository.CreateUserParams{RealmID: realm.ID,
		Username: "u-" + uuid.NewString()[:8], Email: uuid.NewString()[:8] + "@example.com"})
	require.NoError(t, err)
	sess, err := entstore.NewSessionRepository(client).Create(ctx, repository.CreateSessionParams{
		RealmID: realm.ID, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), TokenHash: uuid.NewString()})
	require.NoError(t, err)
	clients := entstore.NewClientRepository(client)
	a, err := clients.Create(ctx, repository.CreateClientAppParams{RealmID: realm.ID, Name: "a", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)
	b, err := clients.Create(ctx, repository.CreateClientAppParams{RealmID: realm.ID, Name: "b", Protocol: domain.ClientAppProtocolOIDC})
	require.NoError(t, err)

	tokens := entstore.NewTokenRepository(client)
	mk := func(clientRef string) *domain.Token {
		tok, err := tokens.Create(ctx, repository.CreateTokenParams{SessionID: sess.ID, ClientRefID: clientRef,
			Type: domain.TokenAccessToken, JTI: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		return tok
	}
	a1, a2, b1 := mk(a.ID), mk(a.ID), mk(b.ID)
	require.NoError(t, tokens.Revoke(ctx, a2.ID))

	n, err := tokens.RevokeByClient(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the one still active")
	for _, c := range []struct {
		tok     *domain.Token
		revoked bool
	}{{a1, true}, {a2, true}, {b1, false}} {
		got, err := tokens.GetByID(ctx, c.tok.ID)
		require.NoError(t, err)
		require.Equal(t, c.revoked, got.Revoked)
	}
}
