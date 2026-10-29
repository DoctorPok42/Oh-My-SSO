package service_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)



func (f *fakeTokenRepo) Create(_ context.Context, p repository.CreateTokenParams) (*domain.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.byJTI[p.JTI]; dup {
		return nil, errors.New("duplicate jti")
	}
	t := &domain.Token{
		ID: "tok-" + p.JTI, SessionID: p.SessionID, ClientRefID: p.ClientRefID, Type: p.Type,
		JTI: p.JTI, ExpiresAt: p.ExpiresAt, Scopes: p.Scopes, TokenHash: p.TokenHash, FamilyID: p.FamilyID,
		Subject: p.Subject, SubjectFormat: p.SubjectFormat,
		IssuedAt: time.Now(),
	}
	f.byJTI[p.JTI] = t
	cp := *t
	return &cp, nil
}

func (f *fakeTokenRepo) GetByID(_ context.Context, id string) (*domain.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.byJTI {
		if t.ID == id {
			cp := *t
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeTokenRepo) GetByHash(_ context.Context, h string) (*domain.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.byJTI {
		if h != "" && t.TokenHash == h {
			cp := *t
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

// MarkUsed mimics the conditional UPDATE of the real repository.
func (f *fakeTokenRepo) MarkUsed(_ context.Context, id string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.byJTI {
		if t.ID == id {
			if t.IsUsed() || t.Revoked {
				return false, nil
			}
			t.UsedAt = at
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeTokenRepo) RevokeFamily(_ context.Context, familyID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, t := range f.byJTI {
		if t.FamilyID == familyID && !t.Revoked {
			t.Revoked = true
			n++
		}
	}
	return n, nil
}

func (f *fakeTokenRepo) get(jti string) domain.Token {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.byJTI[jti]
}

func (f *fakeClientAppRepo) GetByRealmAndClientID(_ context.Context, realmID, clientID string) (*domain.ClientApp, error) {
	for _, c := range f.byID {
		if c.RealmID == realmID && c.ClientID == clientID {
			return c, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeClientAppRepo) ListScopes(context.Context, string) ([]*domain.ClientScope, error) {
	return []*domain.ClientScope{{ID: "s-groups", RealmID: realmA, Name: "groups"}}, nil
}

func (f *fakeAuditRepo) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}


func issue(t *testing.T, f *coreFixture, sessionID string, withRefresh bool) *core.IssuedTokens {
	t.Helper()
	out, err := f.core.IssueTokens(context.Background(), core.TokenRequest{
		SessionID: sessionID, ClientRef: clientOIDC, Scopes: []string{"openid", "email"}, WithRefreshToken: withRefresh,
	})
	require.NoError(t, err)
	return out
}

func TestIdentityCore_IssueTokens(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	sess := f.aliceSession(t)

	t.Run("access + refresh, one family, hashed refresh token", func(t *testing.T) {
		out := issue(t, f, sess.Session.ID, true)
		require.NotEmpty(t, out.FamilyID)
		require.NotEmpty(t, out.Access.JTI)
		require.Equal(t, domain.TokenAccessToken, out.Access.Type)
		require.Equal(t, f.now.Add(5*time.Minute), out.Access.ExpiresAt, "default access token lifetime")
		require.Equal(t, []string{"openid", "email"}, out.Access.Scopes)

		require.Len(t, out.RefreshToken, 52)
		require.Equal(t, domain.TokenRefreshToken, out.Refresh.Type)
		require.Equal(t, out.FamilyID, out.Refresh.FamilyID)
		require.Equal(t, out.FamilyID, out.Access.FamilyID)
		require.Equal(t, service.HashSessionToken(out.RefreshToken), out.Refresh.TokenHash)
		require.NotContains(t, out.Refresh.TokenHash, out.RefreshToken, "only the hash is stored")
		// No refresh token outlives the session (8 h), even if the client asks 30 days.
		require.Equal(t, sess.Session.ExpiresAt, out.Refresh.ExpiresAt)
	})

	t.Run("access token only", func(t *testing.T) {
		out := issue(t, f, sess.Session.ID, false)
		require.Empty(t, out.RefreshToken)
		require.Nil(t, out.Refresh)
	})

	t.Run("lifetimes come from the client, capped by the session", func(t *testing.T) {
		f.clients.byID[clientOIDC].AccessTokenTTL = 60
		defer func() { f.clients.byID[clientOIDC].AccessTokenTTL = 0 }()
		out := issue(t, f, sess.Session.ID, false)
		require.Equal(t, f.now.Add(time.Minute), out.Access.ExpiresAt)

		f.clients.byID[clientOIDC].AccessTokenTTL = 48 * 3600
		out = issue(t, f, sess.Session.ID, false)
		require.Equal(t, sess.Session.ExpiresAt, out.Access.ExpiresAt)
	})

	t.Run("refused when the user may not use the client", func(t *testing.T) {
		f.clients.byID[clientOther] = &domain.ClientApp{ID: clientOther, RealmID: realmA,
			Protocol: domain.ClientAppProtocolOIDC, Status: domain.ClientAppActive, ClientID: "other"}
		_, err := f.core.IssueTokens(ctx, core.TokenRequest{SessionID: sess.Session.ID, ClientRef: clientOther})
		require.ErrorIs(t, err, core.ErrForbidden)
	})

	t.Run("refused for a revoked session", func(t *testing.T) {
		other := f.aliceSession(t)
		require.NoError(t, f.core.RevokeSession(ctx, other.Session.ID, domain.SessionRevokedUserLogout))
		_, err := f.core.IssueTokens(ctx, core.TokenRequest{SessionID: other.Session.ID, ClientRef: clientOIDC})
		require.ErrorIs(t, err, core.ErrSessionInvalid)
	})
}

func TestIdentityCore_RefreshTokenRotation(t *testing.T) {
	ctx := context.Background()

	t.Run("rotation gives a new pair in the same family", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		first := issue(t, f, sess.Session.ID, true)

		next, err := f.core.RotateRefreshToken(ctx, first.RefreshToken, clientOIDC, nil)
		require.NoError(t, err)
		require.NotEqual(t, first.RefreshToken, next.RefreshToken)
		require.Equal(t, first.FamilyID, next.FamilyID)
		require.Equal(t, first.Refresh.Scopes, next.Refresh.Scopes, "nil scopes: same as before")
		require.True(t, f.tokens.get(first.Refresh.JTI).IsUsed())
		require.False(t, f.tokens.get(next.Refresh.JTI).IsUsed())

		narrower, err := f.core.RotateRefreshToken(ctx, next.RefreshToken, clientOIDC, []string{"openid"})
		require.NoError(t, err)
		require.Equal(t, []string{"openid"}, narrower.Access.Scopes, "a refresh can narrow the scopes")

		_, err = f.core.RotateRefreshToken(ctx, narrower.RefreshToken, clientOIDC, []string{"openid", "email"})
		require.ErrorIs(t, err, core.ErrTokenInvalid, "...but never widen them")
	})

	t.Run("a replayed refresh token revokes the whole family", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		first := issue(t, f, sess.Session.ID, true)
		next, err := f.core.RotateRefreshToken(ctx, first.RefreshToken, clientOIDC, nil)
		require.NoError(t, err)

		_, err = f.core.RotateRefreshToken(ctx, first.RefreshToken, clientOIDC, nil)
		require.ErrorIs(t, err, core.ErrTokenReused)

		for _, jti := range []string{first.Access.JTI, first.Refresh.JTI, next.Access.JTI, next.Refresh.JTI} {
			require.True(t, f.tokens.get(jti).Revoked, "token %s must be revoked", jti)
		}
		_, err = f.core.RotateRefreshToken(ctx, next.RefreshToken, clientOIDC, nil)
		require.ErrorIs(t, err, core.ErrTokenInvalid, "the thief's (or the app's) newer token is dead too")
		require.Contains(t, f.audit.actions(), "refresh_token_reuse_detected")

		// The session itself is not revoked: the user just logs in again.
		_, err = f.core.GetSession(ctx, sess.Session.ID)
		require.NoError(t, err)
	})

	t.Run("another client cannot use (nor burn) the token", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		first := issue(t, f, sess.Session.ID, true)
		_, err := f.core.RotateRefreshToken(ctx, first.RefreshToken, clientLongTTL, nil)
		require.ErrorIs(t, err, core.ErrTokenInvalid)
		_, err = f.core.RotateRefreshToken(ctx, first.RefreshToken, clientOIDC, nil)
		require.NoError(t, err, "the rightful client can still use it")
	})

	t.Run("garbage, access tokens and expired tokens are invalid", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		first := issue(t, f, sess.Session.ID, true)
		for _, raw := range []string{"", "nope", first.Access.JTI} {
			_, err := f.core.InspectRefreshToken(ctx, raw)
			require.ErrorIs(t, err, core.ErrTokenInvalid, "raw=%q", raw)
		}
		f.advance(9 * time.Hour) // past the session's 8 h, and so past the token
		_, err := f.core.InspectRefreshToken(ctx, first.RefreshToken)
		require.ErrorIs(t, err, core.ErrTokenInvalid)
	})

	t.Run("refreshing is activity: it keeps the SSO session alive", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		tok := issue(t, f, sess.Session.ID, true)
		// Idle timeout is 10 minutes: three refreshes 9 minutes apart keep
		// the session alive for 27 minutes.
		for i := 0; i < 3; i++ {
			f.advance(9 * time.Minute)
			next, err := f.core.RotateRefreshToken(ctx, tok.RefreshToken, clientOIDC, nil)
			require.NoError(t, err, "refresh #%d", i+1)
			tok = next
		}
		// Then the app stops refreshing: the session idles out, and so do its refresh tokens.
		f.advance(11 * time.Minute)
		_, err := f.core.RotateRefreshToken(ctx, tok.RefreshToken, clientOIDC, nil)
		require.ErrorIs(t, err, core.ErrSessionInvalid)
	})

	t.Run("logout ends every refresh token of the session", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		tok := issue(t, f, sess.Session.ID, true)
		require.NoError(t, f.core.RevokeSession(ctx, sess.Session.ID, domain.SessionRevokedUserLogout))
		_, err := f.core.RotateRefreshToken(ctx, tok.RefreshToken, clientOIDC, nil)
		require.ErrorIs(t, err, core.ErrTokenInvalid)
	})

	t.Run("concurrent refreshes with the same token: a replay, the family dies", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t)
		tok := issue(t, f, sess.Session.ID, true)

		var wins, reused atomic.Int32
		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := f.core.RotateRefreshToken(ctx, tok.RefreshToken, clientOIDC, nil)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, core.ErrTokenReused), errors.Is(err, core.ErrTokenInvalid):
					reused.Add(1)
				default:
					panic(fmt.Sprintf("unexpected error: %v", err))
				}
			}()
		}
		wg.Wait()
		// At most one request got a new pair (and even that one may have
		// lost the race against the replay check)...
		require.LessOrEqual(t, wins.Load(), int32(1))
		require.Equal(t, int32(20), wins.Load()+reused.Load())
		// ...and in every interleaving, nothing of the family survives.
		f.tokens.mu.Lock()
		defer f.tokens.mu.Unlock()
		for _, tk := range f.tokens.byJTI {
			if tk.FamilyID == tok.FamilyID {
				require.True(t, tk.Revoked, "token %s of the family survived", tk.JTI)
			}
		}
	})
}

func TestIdentityCore_ProtocolClients(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	secret, hash := service.NewClientSecret()
	conf := f.clients.byID[clientOIDC]
	conf.ClientType, conf.ClientSecretHash = domain.ClientAppTypeConfidential, hash

	pc, err := f.core.LookupClient(ctx, realmA, domain.ClientAppProtocolOIDC, "app-public-id")
	require.NoError(t, err)
	require.Equal(t, clientOIDC, pc.App.ID)
	require.Equal(t, []string{"groups"}, scopeNames(pc.Scopes))

	for name, call := range map[string]func() error{
		"unknown client_id": func() error {
			_, err := f.core.LookupClient(ctx, realmA, domain.ClientAppProtocolOIDC, "nope")
			return err
		},
		"other realm": func() error {
			_, err := f.core.LookupClient(ctx, "realm-b", domain.ClientAppProtocolOIDC, "app-public-id")
			return err
		},
		"empty id": func() error {
			_, err := f.core.LookupClient(ctx, realmA, domain.ClientAppProtocolOIDC, "")
			return err
		},
	} {
		require.ErrorIs(t, call(), core.ErrClientNotFound, name)
	}

	require.NoError(t, f.core.AuthenticateClient(ctx, clientOIDC, secret))
	require.ErrorIs(t, f.core.AuthenticateClient(ctx, clientOIDC, secret+"x"), core.ErrInvalidClientSecret)
	require.ErrorIs(t, f.core.AuthenticateClient(ctx, clientOIDC, ""), core.ErrInvalidClientSecret)
	require.ErrorIs(t, f.core.AuthenticateClient(ctx, "nope", secret), core.ErrInvalidClientSecret)

	conf.Status = domain.ClientAppSuspended
	_, err = f.core.LookupClient(ctx, realmA, domain.ClientAppProtocolOIDC, "app-public-id")
	require.ErrorIs(t, err, core.ErrClientNotFound, "a suspended client is invisible")
	require.ErrorIs(t, f.core.AuthenticateClient(ctx, clientOIDC, secret), core.ErrInvalidClientSecret)

	conf.Status, conf.ClientType = domain.ClientAppActive, domain.ClientAppTypePublic
	require.ErrorIs(t, f.core.AuthenticateClient(ctx, clientOIDC, secret), core.ErrInvalidClientSecret,
		"a public client never authenticates with a secret, even a leftover one")
}

func TestIdentityCore_AssertionGroupsAndRoles(t *testing.T) {
	f := newCoreFixture(t)
	sess := f.aliceSession(t)
	a, err := f.core.IssueIdentityAssertion(context.Background(), sess.Session.ID, clientOIDC, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"role-app"}, a.UserAttributes["roles"])
	require.Equal(t, []string{}, a.UserAttributes["groups"])
}
