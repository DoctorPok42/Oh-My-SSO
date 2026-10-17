package mfastore

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-process Store for tests (and a single-instance dev
// server). It is safe for concurrent use.
type Memory struct {
	mu         sync.Mutex
	now        func() time.Time
	items      map[string]memItem
	attempts   map[string]memCounter
	ceremonies map[string]memCeremony
}

type memCeremony struct {
	c   Ceremony
	exp time.Time
}

type memItem struct {
	c   LoginChallenge
	exp time.Time
}

type memCounter struct {
	n   int64
	exp time.Time
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store. now may be nil (time.Now).
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{now: now, items: map[string]memItem{}, attempts: map[string]memCounter{}, ceremonies: map[string]memCeremony{}}
}

func (m *Memory) SaveChallenge(_ context.Context, key string, c LoginChallenge, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = memItem{c: c, exp: m.now().Add(ttl)}
	return nil
}

func (m *Memory) GetChallenge(_ context.Context, key string) (*LoginChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[key]
	if !ok || !m.now().Before(it.exp) {
		delete(m.items, key)
		return nil, nil
	}
	c := it.c
	return &c, nil
}

func (m *Memory) IncrementAttempts(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.attempts[key]
	if !ok || !m.now().Before(c.exp) {
		c = memCounter{exp: m.now().Add(ttl)}
	}
	c.n++
	m.attempts[key] = c
	return c.n, nil
}

func (m *Memory) TakeChallenge(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[key]
	delete(m.items, key)
	delete(m.attempts, key)
	return ok && m.now().Before(it.exp), nil
}

func (m *Memory) SaveCeremony(_ context.Context, key string, c Ceremony, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ceremonies[key] = memCeremony{c: c, exp: m.now().Add(ttl)}
	return nil
}

func (m *Memory) TakeCeremony(_ context.Context, key string) (*Ceremony, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.ceremonies[key]
	delete(m.ceremonies, key)
	if !ok || !m.now().Before(it.exp) {
		return nil, nil
	}
	c := it.c
	return &c, nil
}
