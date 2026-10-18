package oidcstore

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-process Store for tests (and a single-instance dev
// server). It is safe for concurrent use.
type Memory struct {
	mu    sync.Mutex
	now   func() time.Time
	items map[string]memItem
}

type memItem struct {
	v   []byte
	exp time.Time
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store. now may be nil (time.Now).
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{now: now, items: map[string]memItem{}}
}

func (m *Memory) Put(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = memItem{v: clone(value), exp: m.now().Add(ttl)}
	return nil
}

func (m *Memory) PutIfAbsent(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.live(key); ok {
		return false, nil
	}
	m.items[key] = memItem{v: clone(value), exp: m.now().Add(ttl)}
	return true, nil
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.live(key)
	if !ok {
		return nil, nil
	}
	return clone(it.v), nil
}

func (m *Memory) Take(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.live(key)
	if !ok {
		return nil, nil
	}
	delete(m.items, key)
	return it.v, nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

// live returns the item if it exists and has not expired. Caller holds mu.
func (m *Memory) live(key string) (memItem, bool) {
	it, ok := m.items[key]
	if !ok {
		return memItem{}, false
	}
	if !m.now().Before(it.exp) {
		delete(m.items, key)
		return memItem{}, false
	}
	return it, true
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
