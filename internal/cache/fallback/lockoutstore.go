package fallback

import (
	"context"
	"sync"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/lockoutstore"
)

// maxLockoutEntries bounds the memory of the lockout counters during an
// outage (a few dozen bytes each).
const maxLockoutEntries = 100_000

// LockoutStore holds the lockout counters kept outside the database (the
// identifiers without an account, the known devices of an account): in
// Valkey, and in this server's memory while Valkey is unavailable.
//
// Unlike the flow stores, memory is used only while Valkey does not answer:
// counters do not span an outage. During one, they start from zero on each
// server; afterwards, Valkey's are used again. The lockout of accounts is in
// the database and does not change. Without this, a sign-in with an
// unknown identifier would fail during an outage while one with a known
// identifier works: the difference would tell which identifiers exist.
type LockoutStore struct {
	primary lockoutstore.Store

	mu    sync.Mutex
	items *ttlMap[string] // lockoutstore.Encode of the state
}

var _ lockoutstore.Store = (*LockoutStore)(nil)

// NewLockoutStore wraps primary (Valkey). now may be nil (time.Now).
func NewLockoutStore(primary lockoutstore.Store, now func() time.Time) *LockoutStore {
	return &LockoutStore{primary: primary, items: newTTLMap[string](now, maxLockoutEntries)}
}

func (s *LockoutStore) Get(ctx context.Context, key string) (domain.LockoutState, error) {
	st, err := s.primary.Get(ctx, key)
	if !unavailable(err) {
		return st, err
	}
	s.mu.Lock()
	raw, _ := s.items.get(key)
	s.mu.Unlock()
	return lockoutstore.Decode(raw)
}

// CompareAndSwap swaps in whichever store answers now. When Valkey comes
// back between the read (from memory) and the swap, the swap compares old
// with Valkey's state: unless they are equal, it reports false and the
// caller reads again, from Valkey.
func (s *LockoutStore) CompareAndSwap(ctx context.Context, key string, old, next domain.LockoutState, ttl time.Duration) (bool, error) {
	ok, err := s.primary.CompareAndSwap(ctx, key, old, next, ttl)
	if !unavailable(err) {
		return ok, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := s.items.get(key)
	if raw != lockoutstore.Encode(old) {
		return false, nil
	}
	if enc := lockoutstore.Encode(next); enc == "" {
		s.items.delete(key)
	} else if err := s.items.set(key, enc, ttl); err != nil {
		return false, err
	}
	return true, nil
}
