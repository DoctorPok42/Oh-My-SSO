package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// countingRealms is a RealmRepository that counts GetByName.
type countingRealms struct {
	repository.RealmRepository
	mu     sync.Mutex
	byName map[string]domain.Realm
	err    error
	calls  int
}

func (c *countingRealms) GetByName(_ context.Context, name string) (*domain.Realm, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	r, ok := c.byName[name]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &r, nil
}

func (c *countingRealms) set(name string, r domain.Realm) {
	c.mu.Lock()
	c.byName[name] = r
	c.mu.Unlock()
}

func (c *countingRealms) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestRealmCache(t *testing.T) {
	ctx := context.Background()
	repo := &countingRealms{byName: map[string]domain.Realm{
		"acme": {ID: "r1", Name: "acme", DisplayName: "Acme", Status: domain.RealmActive},
	}}
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	s := &Server{realms: repo}
	s.realmCache.now = func() time.Time { return now }

	for range 5 {
		r, err := s.realmByName(ctx, "acme")
		require.NoError(t, err)
		require.Equal(t, "Acme", r.DisplayName)
	}
	require.Equal(t, 1, repo.count(), "read once a minute, not on every request")

	// Each caller has its own copy.
	r, _ := s.realmByName(ctx, "acme")
	r.DisplayName = "changed by a handler"
	r2, _ := s.realmByName(ctx, "acme")
	require.Equal(t, "Acme", r2.DisplayName)

	// A change (realm disabled) is seen within a minute.
	repo.set("acme", domain.Realm{ID: "r1", Name: "acme", DisplayName: "Acme", Status: domain.RealmInactive})
	now = now.Add(59 * time.Second)
	r, _ = s.realmByName(ctx, "acme")
	require.Equal(t, domain.RealmActive, r.Status, "still the cached copy")
	now = now.Add(time.Second)
	r, _ = s.realmByName(ctx, "acme")
	require.Equal(t, domain.RealmInactive, r.Status)

	// A name that matches no realm is asked every time: created later, found at once.
	calls := repo.count()
	_, err := s.realmByName(ctx, "later")
	require.ErrorIs(t, err, repository.ErrNotFound)
	repo.set("later", domain.Realm{ID: "r2", Name: "later", Status: domain.RealmActive})
	r, err = s.realmByName(ctx, "later")
	require.NoError(t, err)
	require.Equal(t, "r2", r.ID)
	require.Equal(t, calls+2, repo.count())

	// A failed lookup is not kept either.
	now = now.Add(time.Minute)
	repo.err = errors.New("database down")
	_, err = s.realmByName(ctx, "acme")
	require.Error(t, err)
	repo.err = nil
	_, err = s.realmByName(ctx, "acme")
	require.NoError(t, err)
}

func TestRealmMiddlewareUsesTheCache(t *testing.T) {
	repo := &countingRealms{byName: map[string]domain.Realm{
		"acme":   {ID: "r1", Name: "acme", Status: domain.RealmActive},
		"closed": {ID: "r2", Name: "closed", Status: domain.RealmInactive},
	}}
	s := New(nil, nil, nil, repo, nil, nil)
	// The realm middleware answers realm_not_found itself; past it, this bare
	// server has no route (chi's own 404).
	get := func(path string) string {
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Body.String()
	}
	for range 3 {
		require.NotContains(t, get("/r/acme/nothing"), "realm_not_found")
	}
	require.Equal(t, 1, repo.count())
	require.Contains(t, get("/r/closed/nothing"), "realm_not_found", "a disabled realm still answers 404")
	require.Contains(t, get("/r/nowhere/nothing"), "realm_not_found")
}
