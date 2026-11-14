package httpserver

import (
	"context"
	"sync"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// realmCacheTTL: how long the public server keeps a realm it found by name.
// Every request under /r/<realm> needs it, JWKS, discovery and static files
// included: without the cache, each one is a database query (audit B-19).
// A change to a realm (disabled or enabled again, display name) reaches this
// server within that time, as the realm settings do (settingsCache). Nothing
// renames or deletes a realm: the Admin API changes its display name and status.
const realmCacheTTL = time.Minute

// realmCache holds the realms found by name. A name that matches no realm
// is not kept (a realm created a moment later is found at once), nor is a
// failed lookup: it holds existing realms only, and cannot grow beyond them.
type realmCache struct {
	mu    sync.Mutex
	now   func() time.Time
	items map[string]realmCacheEntry
}

type realmCacheEntry struct {
	realm domain.Realm
	at    time.Time
}

// clock: now may be left nil (time.Now), so is items: a zero realmCache works.
func (c *realmCache) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// realmByName is realms.GetByName through the cache. Each caller gets its
// own copy: a request cannot change what the others read.
func (s *Server) realmByName(ctx context.Context, name string) (*domain.Realm, error) {
	c := &s.realmCache
	c.mu.Lock()
	if e, ok := c.items[name]; ok && c.clock().Sub(e.at) < realmCacheTTL {
		c.mu.Unlock()
		r := e.realm
		return &r, nil
	}
	c.mu.Unlock()

	realm, err := s.realms.GetByName(ctx, name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		delete(c.items, name)
		return nil, err
	}
	if c.items == nil {
		c.items = map[string]realmCacheEntry{}
	}
	c.items[name] = realmCacheEntry{realm: *realm, at: c.clock()}
	r := *realm
	return &r, nil
}
