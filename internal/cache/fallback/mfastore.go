package fallback

import (
	"context"
	"sync"
	"time"

	"sso.internal/sso/internal/mfastore"
)

// maxMFAEntries bounds the memory of the MFA store during an outage.
const maxMFAEntries = 50_000

// MFAStore is the mfastore.Store of the second factor: Valkey, and this
// server's memory while Valkey is unavailable. Same rule as FlowStore: a key
// lives where it was last written, memory is looked at first, and a
// challenge or ceremony taken from memory stays taken (tombstone) until any
// older copy in Valkey has expired. The attempts of a challenge are counted
// where the challenge lives.
type MFAStore struct {
	primary mfastore.Store

	mu         sync.Mutex
	challenges *ttlMap[*mfastore.LoginChallenge] // nil: taken
	attempts   *ttlMap[int64]
	ceremonies *ttlMap[*mfastore.Ceremony] // nil: taken
	tomb       tombstones
}

var _ mfastore.Store = (*MFAStore)(nil)

// NewMFAStore wraps primary (Valkey). now may be nil (time.Now).
func NewMFAStore(primary mfastore.Store, now func() time.Time) *MFAStore {
	return &MFAStore{
		primary:    primary,
		challenges: newTTLMap[*mfastore.LoginChallenge](now, maxMFAEntries),
		attempts:   newTTLMap[int64](now, maxMFAEntries),
		ceremonies: newTTLMap[*mfastore.Ceremony](now, maxMFAEntries),
	}
}

func (s *MFAStore) hasChallenge(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.challenges.get(key)
	return ok
}

func (s *MFAStore) hasCeremony(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ceremonies.get(key)
	return ok
}

func (s *MFAStore) SaveChallenge(ctx context.Context, key string, c mfastore.LoginChallenge, ttl time.Duration) error {
	s.saw(ttl)
	if !s.hasChallenge(key) {
		err := s.primary.SaveChallenge(ctx, key, c, ttl)
		if !unavailable(err) {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts.delete(key)
	return s.challenges.set(key, &c, ttl)
}

func (s *MFAStore) GetChallenge(ctx context.Context, key string) (*mfastore.LoginChallenge, error) {
	s.mu.Lock()
	c, ok := s.challenges.get(key)
	s.mu.Unlock()
	if !ok {
		return s.primary.GetChallenge(ctx, key)
	}
	if c == nil {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (s *MFAStore) IncrementAttempts(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	if _, ok := s.challenges.get(key); !ok {
		s.mu.Unlock()
		return s.primary.IncrementAttempts(ctx, key, ttl)
	}
	defer s.mu.Unlock()
	n, ok := s.attempts.get(key)
	if !ok {
		n = 0
	}
	n++
	if err := s.attempts.set(key, n, ttl); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *MFAStore) TakeChallenge(ctx context.Context, key string) (bool, error) {
	s.mu.Lock()
	c, ok := s.challenges.get(key)
	if !ok {
		s.mu.Unlock()
		return s.primary.TakeChallenge(ctx, key)
	}
	defer s.mu.Unlock()
	s.attempts.delete(key)
	if c == nil {
		return false, nil
	}
	_ = s.challenges.set(key, nil, s.tomb.ttl()) // an existing key: never refused
	return true, nil
}

func (s *MFAStore) SaveCeremony(ctx context.Context, key string, c mfastore.Ceremony, ttl time.Duration) error {
	s.saw(ttl)
	if !s.hasCeremony(key) {
		err := s.primary.SaveCeremony(ctx, key, c, ttl)
		if !unavailable(err) {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ceremonies.set(key, &c, ttl)
}

func (s *MFAStore) TakeCeremony(ctx context.Context, key string) (*mfastore.Ceremony, error) {
	s.mu.Lock()
	c, ok := s.ceremonies.get(key)
	if !ok {
		s.mu.Unlock()
		return s.primary.TakeCeremony(ctx, key)
	}
	defer s.mu.Unlock()
	if c == nil {
		return nil, nil
	}
	_ = s.ceremonies.set(key, nil, s.tomb.ttl())
	cp := *c
	return &cp, nil
}

func (s *MFAStore) saw(ttl time.Duration) {
	s.mu.Lock()
	s.tomb.saw(ttl)
	s.mu.Unlock()
}
