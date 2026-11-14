package fallback

import (
	"context"
	"sync"
	"time"

	"sso.internal/sso/internal/oidcstore"
)

// maxFlowEntries bounds the memory of the flow store during an outage (an
// authorization request is about 1 KiB): /authorize needs no credentials.
const maxFlowEntries = 50_000

// FlowStore is the oidcstore.Store of the OIDC and SAML flows: Valkey, and
// this server's memory while Valkey is unavailable.
//
// A key lives where it was last written: in Valkey, or in memory when
// Valkey did not answer then. Every call looks in memory first, so a flow
// started during an outage goes on after it, and a key that memory holds
// hides any older value Valkey may still have. For the same reason a key
// deleted while memory holds it, or while Valkey does not answer, is kept
// as deleted (a tombstone) until any copy in Valkey has expired. A key that
// memory does not hold is read from Valkey only: while it is unavailable,
// reading it fails.
type FlowStore struct {
	primary oidcstore.Store

	mu    sync.Mutex
	items *ttlMap[flowItem]
	tomb  tombstones
}

// flowItem is a value, or a tombstone when deleted is set.
type flowItem struct {
	v       []byte
	deleted bool
}

var _ oidcstore.Store = (*FlowStore)(nil)

// NewFlowStore wraps primary (Valkey). now may be nil (time.Now).
func NewFlowStore(primary oidcstore.Store, now func() time.Time) *FlowStore {
	return &FlowStore{primary: primary, items: newTTLMap[flowItem](now, maxFlowEntries)}
}

// local returns what memory holds for key: a value, a tombstone, or nothing.
func (s *FlowStore) local(key string) (flowItem, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items.get(key)
}

func (s *FlowStore) saw(ttl time.Duration) {
	s.mu.Lock()
	s.tomb.saw(ttl)
	s.mu.Unlock()
}

// putLocal stores value in memory. Caller holds mu.
func (s *FlowStore) putLocal(key string, value []byte, ttl time.Duration) error {
	s.tomb.saw(ttl)
	return s.items.set(key, flowItem{v: append([]byte(nil), value...)}, ttl)
}

// buryLocal marks key deleted in memory. Caller holds mu.
func (s *FlowStore) buryLocal(key string) {
	// A full map keeps the key's current entry if it has one: set refuses
	// new keys only.
	_ = s.items.set(key, flowItem{deleted: true}, s.tomb.ttl())
}

func (s *FlowStore) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if _, ok := s.local(key); !ok {
		s.saw(ttl)
		err := s.primary.Put(ctx, key, value, ttl)
		if !unavailable(err) {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocal(key, value, ttl)
}

func (s *FlowStore) PutIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if _, ok := s.local(key); !ok {
		s.saw(ttl)
		first, err := s.primary.PutIfAbsent(ctx, key, value, ttl)
		if !unavailable(err) {
			return first, err
		}
	}
	// Checked and written under one lock: of two concurrent calls, one wins.
	s.mu.Lock()
	defer s.mu.Unlock()
	if it, ok := s.items.get(key); ok && !it.deleted {
		return false, nil
	}
	if err := s.putLocal(key, value, ttl); err != nil {
		return false, err
	}
	return true, nil
}

func (s *FlowStore) Get(ctx context.Context, key string) ([]byte, error) {
	if it, ok := s.local(key); ok {
		if it.deleted {
			return nil, nil
		}
		return append([]byte(nil), it.v...), nil
	}
	return s.primary.Get(ctx, key)
}

func (s *FlowStore) Take(ctx context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	if it, ok := s.items.get(key); ok {
		// Read and delete under one lock: a value is taken once.
		if !it.deleted {
			s.buryLocal(key)
		}
		s.mu.Unlock()
		if it.deleted {
			return nil, nil
		}
		return it.v, nil
	}
	s.mu.Unlock()
	return s.primary.Take(ctx, key)
}

func (s *FlowStore) Delete(ctx context.Context, key string) error {
	if _, ok := s.local(key); !ok {
		err := s.primary.Delete(ctx, key)
		if !unavailable(err) {
			return err
		}
		// Valkey may hold the key: remember it is gone.
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buryLocal(key)
	return nil
}
