package lockoutstore

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// Store is implemented by Valkey (production) and Memory (tests).
type Store interface {
	// Get returns the state of key, or the zero state when unknown/expired.
	Get(ctx context.Context, key string) (domain.LockoutState, error)
	// CompareAndSwap stores next (for ttl) only if the stored state still
	// equals old, and tells whether it did. A zero next deletes the key.
	CompareAndSwap(ctx context.Context, key string, old, next domain.LockoutState, ttl time.Duration) (bool, error)
}

// wire is the stored form: times as Unix milliseconds, so that encoding a
// decoded state gives back exactly the same string (CompareAndSwap compares
// strings).
type wire struct {
	F  int   `json:"f,omitempty"`
	LF int64 `json:"lf,omitempty"`
	LU int64 `json:"lu,omitempty"`
	LC int   `json:"lc,omitempty"`
	LL int64 `json:"ll,omitempty"`
}

// Encode returns the canonical stored form of s ("" for the zero state).
func Encode(s domain.LockoutState) string {
	if s.IsZero() {
		return ""
	}
	b, _ := json.Marshal(wire{
		F: s.FailedCount, LF: ms(s.LastFailedAt), LU: ms(s.LockedUntil),
		LC: s.LockCount, LL: ms(s.LastLockedAt),
	})
	return string(b)
}

// Decode parses the output of Encode ("" gives the zero state).
func Decode(raw string) (domain.LockoutState, error) {
	if raw == "" {
		return domain.LockoutState{}, nil
	}
	var w wire
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		return domain.LockoutState{}, err
	}
	return domain.LockoutState{
		FailedCount: w.F, LastFailedAt: fromMS(w.LF), LockedUntil: fromMS(w.LU),
		LockCount: w.LC, LastLockedAt: fromMS(w.LL),
	}, nil
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

// Memory is an in-process Store, for tests and single-process development.
type Memory struct {
	mu   sync.Mutex
	now  func() time.Time
	data map[string]memEntry
}

type memEntry struct {
	raw     string
	expires time.Time
}

// NewMemory returns an empty store. now may be nil (time.Now).
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{now: now, data: map[string]memEntry{}}
}

func (m *Memory) Get(_ context.Context, key string) (domain.LockoutState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Decode(m.current(key))
}

func (m *Memory) CompareAndSwap(_ context.Context, key string, old, next domain.LockoutState, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current(key) != Encode(old) {
		return false, nil
	}
	if raw := Encode(next); raw == "" {
		delete(m.data, key)
	} else {
		m.data[key] = memEntry{raw: raw, expires: m.now().Add(ttl)}
	}
	return true, nil
}

// current returns the stored string, "" if missing or expired. Caller holds mu.
func (m *Memory) current(key string) string {
	e, ok := m.data[key]
	if !ok {
		return ""
	}
	if !m.now().Before(e.expires) {
		delete(m.data, key)
		return ""
	}
	return e.raw
}
