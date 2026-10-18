package entstore_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// Step 10: what refresh token rotation relies on in Postgres.
func TestTokenRepository_RefreshRotation_Integration(t *testing.T) {
	f := newRBACFixture(t)
	tokens := entstore.NewTokenRepository(f.client)
	clients := entstore.NewClientRepository(f.client)
	u := f.user()
	app := f.clientApp("rotation")
	sess, err := entstore.NewSessionRepository(f.client).Create(f.ctx, repository.CreateSessionParams{
		RealmID: f.realm.ID, UserID: u.ID, TokenHash: "hash-" + f.suffix(),
		ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword,
	})
	require.NoError(t, err)

	family := "family-" + f.suffix()
	newTok := func(typ domain.TokenType, hash string) *domain.Token {
		tok, err := tokens.Create(f.ctx, repository.CreateTokenParams{
			SessionID: sess.ID, ClientRefID: app.ID, Type: typ, JTI: "jti-" + f.suffix(),
			ExpiresAt: time.Now().Add(time.Hour), Scopes: []string{"openid"}, TokenHash: hash, FamilyID: family,
		})
		require.NoError(t, err)
		return tok
	}
	access := newTok(domain.TokenAccessToken, "")
	refresh := newTok(domain.TokenRefreshToken, "rt-hash-"+f.suffix())
	newTok(domain.TokenAccessToken, "") // a second access token without hash: NULLs do not collide

	t.Run("lookup by hash", func(t *testing.T) {
		got, err := tokens.GetByHash(f.ctx, refresh.TokenHash)
		require.NoError(t, err)
		require.Equal(t, refresh.ID, got.ID)
		require.Equal(t, family, got.FamilyID)
		require.False(t, got.IsUsed())
		_, err = tokens.GetByHash(f.ctx, "unknown")
		require.ErrorIs(t, err, repository.ErrNotFound)
		_, err = tokens.GetByHash(f.ctx, "")
		require.ErrorIs(t, err, repository.ErrNotFound, "access tokens have no hash: never matched")
	})

	t.Run("the hash is unique", func(t *testing.T) {
		_, err := tokens.Create(f.ctx, repository.CreateTokenParams{
			SessionID: sess.ID, ClientRefID: app.ID, Type: domain.TokenRefreshToken, JTI: "jti-" + f.suffix(),
			ExpiresAt: time.Now().Add(time.Hour), TokenHash: refresh.TokenHash,
		})
		require.Error(t, err)
	})

	t.Run("MarkUsed: one winner among concurrent exchanges", func(t *testing.T) {
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				won, err := tokens.MarkUsed(f.ctx, refresh.ID, time.Now())
				if err == nil && won {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		require.Equal(t, int32(1), wins.Load())
		got, err := tokens.GetByID(f.ctx, refresh.ID)
		require.NoError(t, err)
		require.True(t, got.IsUsed())
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		n, err := tokens.RevokeFamily(f.ctx, family)
		require.NoError(t, err)
		require.Equal(t, 3, n)
		got, err := tokens.GetByJTI(f.ctx, access.JTI)
		require.NoError(t, err)
		require.True(t, got.Revoked)
		n, err = tokens.RevokeFamily(f.ctx, family)
		require.NoError(t, err)
		require.Zero(t, n, "idempotent")

		won, err := tokens.MarkUsed(f.ctx, access.ID, time.Now())
		require.NoError(t, err)
		require.False(t, won, "a revoked token cannot be exchanged")
	})

	t.Run("client grants and scope mapping are idempotent", func(t *testing.T) {
		r := f.role()
		g := f.group()
		cs := f.clientScope("rot-scope-" + f.suffix())
		for range 2 {
			require.NoError(t, clients.GrantRole(f.ctx, app.ID, r.ID, "test"))
			require.NoError(t, clients.GrantGroup(f.ctx, app.ID, g.ID, "test"))
			require.NoError(t, clients.MapScope(f.ctx, app.ID, cs.ID))
		}
		scopes, err := clients.ListScopes(f.ctx, app.ID)
		require.NoError(t, err)
		require.Len(t, scopes, 1)
		require.Equal(t, cs.Name, scopes[0].Name)
	})
}
