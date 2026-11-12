package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/sessioncache"
)

// Revocation against a cache that fails or holds older data: the database
// decides, the tokens never outlive their session.

// memSessionCache behaves like the Valkey cache. failTombstones: that many
// MarkRevoked calls fail first (Valkey not answering).
type memSessionCache struct {
	entries        map[string]sessioncache.Entry
	tombstones     map[string]bool
	failTombstones int
}

func newMemSessionCache() *memSessionCache {
	return &memSessionCache{entries: map[string]sessioncache.Entry{}, tombstones: map[string]bool{}}
}

func (c *memSessionCache) Get(_ context.Context, hash string) (sessioncache.Result, error) {
	if c.tombstones[hash] {
		return sessioncache.Result{Revoked: true}, nil
	}
	if e, ok := c.entries[hash]; ok {
		return sessioncache.Result{Entry: &e}, nil
	}
	return sessioncache.Result{}, nil
}

func (c *memSessionCache) Fill(_ context.Context, hash string, e sessioncache.Entry, _ time.Duration) error {
	if _, ok := c.entries[hash]; !ok {
		c.entries[hash] = e
	}
	return nil
}

func (c *memSessionCache) Refresh(_ context.Context, hash string, e sessioncache.Entry, _ time.Duration) error {
	if _, ok := c.entries[hash]; ok {
		c.entries[hash] = e
	}
	return nil
}

func (c *memSessionCache) MarkRevoked(_ context.Context, hash string, _ time.Duration) error {
	if c.failTombstones > 0 {
		c.failTombstones--
		return errors.New("valkey: connection refused")
	}
	c.tombstones[hash] = true
	delete(c.entries, hash)
	return nil
}

type revocationFixture struct {
	*rememberFixture
	cache  *memSessionCache
	tokens *fakeTokenRepo
	svc    *service.SessionService
}

func newRevocationFixture() *revocationFixture {
	f := &revocationFixture{
		rememberFixture: newRememberFixture(),
		cache:           newMemSessionCache(),
		tokens:          &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
	}
	f.svc = service.NewSessionService(f.sessions, settingsStub{}, f.tokens, f.cache, service.WithClock(f.clock))
	return f
}

// signIn opens a session with one token, and uses it once: it is in the cache.
func (f *revocationFixture) signIn(t *testing.T) (string, *domain.Session) {
	t.Helper()
	raw, sess := f.login(t, f.svc, false)
	_, err := f.svc.Validate(context.Background(), realmA, raw)
	require.NoError(t, err)
	f.tokens.byJTI[sess.ID] = &domain.Token{ID: sess.ID, JTI: sess.ID, SessionID: sess.ID}
	return raw, sess
}

func TestRevokeAllForUser_CacheFailure(t *testing.T) {
	f := newRevocationFixture()
	ctx := context.Background()
	var raws []string
	for range 3 {
		raw, _ := f.signIn(t)
		raws = append(raws, raw)
	}

	f.cache.failTombstones = 1
	require.Error(t, f.svc.RevokeAllForUser(ctx, aliceID, domain.SessionRevokedAdminRevoked))

	for _, tok := range f.tokens.byJTI {
		require.True(t, tok.Revoked, "token of session %s", tok.SessionID)
	}
	require.Len(t, f.cache.tombstones, 2, "the failure on one session does not spare the others")

	// The entry that still says "active" ends at its next activity check.
	f.advance(time.Minute)
	for _, raw := range raws {
		_, err := f.svc.Validate(ctx, realmA, raw)
		require.ErrorIs(t, err, service.ErrSessionInvalid)
	}
	require.Len(t, f.cache.tombstones, 3)
}

func TestRevoke_CacheFailureStillRevokesTokens(t *testing.T) {
	f := newRevocationFixture()
	_, sess := f.signIn(t)

	f.cache.failTombstones = 1
	require.Error(t, f.svc.Revoke(context.Background(), sess.ID, domain.SessionRevokedAdminRevoked))
	require.True(t, f.tokens.byJTI[sess.ID].Revoked)
}

// Valkey back from an older snapshot: the entry of a session revoked since
// is there again, without its tombstone.
func TestValidate_CacheEntryOfRevokedSession(t *testing.T) {
	f := newRevocationFixture()
	ctx := context.Background()
	raw, sess := f.signIn(t)
	require.NoError(t, f.sessions.Revoke(ctx, sess.ID, domain.SessionRevokedAdminRevoked))

	f.advance(time.Minute)
	_, err := f.svc.Validate(ctx, realmA, raw)
	require.ErrorIs(t, err, service.ErrSessionInvalid)
	require.True(t, f.cache.tombstones[service.HashSessionToken(raw)], "the entry is dropped")
}
