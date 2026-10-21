package entstore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 13: what the consent service relies on in Postgres.
func TestConsentRepository_Integration(t *testing.T) {
	f := newRBACFixture(t)
	consents := entstore.NewConsentRepository(f.client)
	u := f.user()
	app := f.clientApp("partner")
	other := f.clientApp("other")

	_, err := consents.GetByUserAndClient(f.ctx, u.ID, app.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)

	c, err := consents.Create(f.ctx, repository.CreateConsentParams{UserID: u.ID, ClientRefID: app.ID, Scopes: []string{"profile"}})
	require.NoError(t, err)
	require.Equal(t, domain.ConsentGranted, c.Status)

	t.Run("one row per user and client", func(t *testing.T) {
		_, err := consents.Create(f.ctx, repository.CreateConsentParams{UserID: u.ID, ClientRefID: app.ID})
		require.ErrorIs(t, err, repository.ErrConflict)
	})

	t.Run("revoke, then grant again", func(t *testing.T) {
		require.NoError(t, consents.Revoke(f.ctx, c.ID))
		got, err := consents.GetByUserAndClient(f.ctx, u.ID, app.ID)
		require.NoError(t, err)
		require.Equal(t, domain.ConsentRevoked, got.Status)
		require.False(t, got.RevokedAt.IsZero())

		status, at := domain.ConsentGranted, time.Now().Truncate(time.Microsecond)
		got, err = consents.Update(f.ctx, c.ID, repository.UpdateConsentParams{
			Scopes: []string{"email"}, Status: &status, GrantedAt: &at, ClearRevokedAt: true,
		})
		require.NoError(t, err)
		require.Equal(t, domain.ConsentGranted, got.Status)
		require.Equal(t, []string{"email"}, got.Scopes)
		require.True(t, got.RevokedAt.IsZero(), "revoked_at cleared")
		require.True(t, got.GrantedAt.Equal(at))
	})

	t.Run("list by user, most recently changed first", func(t *testing.T) {
		_, err := consents.Create(f.ctx, repository.CreateConsentParams{UserID: u.ID, ClientRefID: other.ID, Scopes: []string{}})
		require.NoError(t, err)
		list, err := consents.ListByUser(f.ctx, u.ID)
		require.NoError(t, err)
		require.Len(t, list, 2)
		require.Equal(t, other.ID, list[0].ClientRefID)
		require.Empty(t, list[0].Scopes)
		none, err := consents.ListByUser(f.ctx, f.user().ID)
		require.NoError(t, err)
		require.Empty(t, none)
	})
}

// RevokeByUserAndClient finds tokens through their session: one UPDATE with a
// join on sessions.user_id.
func TestTokenRepository_RevokeByUserAndClient_Integration(t *testing.T) {
	f := newRBACFixture(t)
	tokens := entstore.NewTokenRepository(f.client)
	sessions := entstore.NewSessionRepository(f.client)
	alice, bob := f.user(), f.user()
	app, other := f.clientApp("partner"), f.clientApp("other")

	session := func(u *domain.User) *domain.Session {
		s, err := sessions.Create(f.ctx, repository.CreateSessionParams{
			RealmID: f.realm.ID, UserID: u.ID, TokenHash: "hash-" + f.suffix(),
			ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword,
		})
		require.NoError(t, err)
		return s
	}
	tok := func(s *domain.Session, c *domain.ClientApp, typ domain.TokenType) *domain.Token {
		created, err := tokens.Create(f.ctx, repository.CreateTokenParams{SessionID: s.ID, ClientRefID: c.ID, Type: typ,
			JTI: "jti-" + f.suffix(), ExpiresAt: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		return created
	}
	s1, s2, sb := session(alice), session(alice), session(bob)
	revoked := []*domain.Token{
		tok(s1, app, domain.TokenAccessToken), tok(s1, app, domain.TokenRefreshToken), tok(s2, app, domain.TokenAccessToken),
	}
	kept := []*domain.Token{
		tok(s1, other, domain.TokenAccessToken), // another client
		tok(sb, app, domain.TokenAccessToken),   // another user
		tok(s1, app, domain.TokenSAMLSession),   // Single Logout record
	}

	n, err := tokens.RevokeByUserAndClient(f.ctx, alice.ID, app.ID)
	require.NoError(t, err)
	require.Equal(t, 3, n, "every session of the user")
	for _, x := range revoked {
		got, err := tokens.GetByID(f.ctx, x.ID)
		require.NoError(t, err)
		require.True(t, got.Revoked, x.Type)
	}
	for _, x := range kept {
		got, err := tokens.GetByID(f.ctx, x.ID)
		require.NoError(t, err)
		require.False(t, got.Revoked, x.Type)
	}
	n, err = tokens.RevokeByUserAndClient(f.ctx, alice.ID, app.ID)
	require.NoError(t, err)
	require.Zero(t, n, "idempotent")
}
