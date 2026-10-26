package entstore_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/sessioncache"
	"sso.internal/sso/internal/storage/entstore"
)


func TestRealm_EnsurePairwiseSubjectSalt_Integration(t *testing.T) {
	f := newRBACFixture(t)
	realms := entstore.NewRealmRepository(f.client)

	first, err := realms.EnsurePairwiseSubjectSalt(f.ctx, f.realm.ID, "salt-one")
	require.NoError(t, err)
	require.Equal(t, "salt-one", first)

	// A second candidate never replaces the stored salt.
	again, err := realms.EnsurePairwiseSubjectSalt(f.ctx, f.realm.ID, "salt-two")
	require.NoError(t, err)
	require.Equal(t, "salt-one", again)

	_, err = realms.EnsurePairwiseSubjectSalt(f.ctx, "no-such-realm", "x")
	require.ErrorIs(t, err, repository.ErrNotFound)
}

func TestRealm_EnsurePairwiseSubjectSalt_Concurrent_Integration(t *testing.T) {
	f := newRBACFixture(t)
	realms := entstore.NewRealmRepository(f.client)

	const n = 10
	var wg sync.WaitGroup
	got := make([]string, n)
	for i := range n {
		wg.Go(func() {
			s, err := realms.EnsurePairwiseSubjectSalt(f.ctx, f.realm.ID, "candidate-"+string(rune('a'+i)))
			require.NoError(t, err)
			got[i] = s
		})
	}
	wg.Wait()

	for _, s := range got {
		require.Equal(t, got[0], s, "every concurrent caller must get the same salt")
	}
}

func TestClientApp_SubjectType_Integration(t *testing.T) {
	f := newRBACFixture(t)
	clients := entstore.NewClientRepository(f.client)

	c := f.clientApp("pairwise")
	require.Equal(t, domain.ClientAppSubjectPublic, c.SubjectType, "default must be public")

	pairwise := domain.ClientAppSubjectPairwise
	sector := "https://shop.example.com"
	_, err := clients.Update(f.ctx, c.ID, repository.UpdateClientAppParams{
		SubjectType: &pairwise, SectorIdentifier: &sector,
	})
	require.NoError(t, err)

	got, err := clients.GetByID(f.ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, domain.ClientAppSubjectPairwise, got.SubjectType)
	require.Equal(t, sector, got.SectorIdentifier)

	_, err = clients.GetByID(f.ctx, "no-such-client")
	require.ErrorIs(t, err, repository.ErrNotFound)
}

// noopSessionCache: always a miss, so SessionService talks to Postgres only.
type noopSessionCache struct{}

func (noopSessionCache) Get(context.Context, string) (sessioncache.Result, error) {
	return sessioncache.Result{}, nil
}
func (noopSessionCache) Fill(context.Context, string, sessioncache.Entry, time.Duration) error {
	return nil
}
func (noopSessionCache) Refresh(context.Context, string, sessioncache.Entry, time.Duration) error {
	return nil
}
func (noopSessionCache) MarkRevoked(context.Context, string, time.Duration) error { return nil }

func TestSessionRevoke_CascadesToTokens_Integration(t *testing.T) {
	f := newRBACFixture(t)
	sessionsRepo := entstore.NewSessionRepository(f.client)
	tokens := entstore.NewTokenRepository(f.client)
	svc := service.NewSessionService(sessionsRepo, entstore.NewInstanceSettingsRepository(f.client),
		tokens, noopSessionCache{})

	u := f.user()
	app := f.clientApp("cascade")
	newSession := func(hash string) *domain.Session {
		s, err := sessionsRepo.Create(f.ctx, repository.CreateSessionParams{
			RealmID: f.realm.ID, UserID: u.ID, TokenHash: hash,
			ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword,
		})
		require.NoError(t, err)
		return s
	}
	target, other := newSession("hash-"+f.suffix()), newSession("hash-"+f.suffix())

	newToken := func(sess *domain.Session) *domain.Token {
		tok, err := tokens.Create(f.ctx, repository.CreateTokenParams{
			SessionID: sess.ID, ClientRefID: app.ID, Type: domain.TokenAccessToken,
			JTI: "jti-" + f.suffix(), ExpiresAt: time.Now().Add(time.Hour),
		})
		require.NoError(t, err)
		return tok
	}
	t1, t2, untouched := newToken(target), newToken(target), newToken(other)

	require.NoError(t, svc.Revoke(f.ctx, target.ID, domain.SessionRevokedAdminRevoked))

	for _, tok := range []*domain.Token{t1, t2} {
		got, err := tokens.GetByJTI(f.ctx, tok.JTI)
		require.NoError(t, err)
		require.True(t, got.Revoked, "token %s must be revoked with its session", tok.JTI)
	}
	got, err := tokens.GetByJTI(f.ctx, untouched.JTI)
	require.NoError(t, err)
	require.False(t, got.Revoked, "tokens of other sessions must stay valid")

	// Unknown jti: the repository speaks repository.ErrNotFound, not Ent.
	_, err = tokens.GetByJTI(f.ctx, "no-such-jti")
	require.ErrorIs(t, err, repository.ErrNotFound)
}
