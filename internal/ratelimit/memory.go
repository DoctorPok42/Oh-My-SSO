package ratelimit

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMemoryKeys is how many keys a Memory limiter holds at most.
const DefaultMemoryKeys = 100_000

// memoryMember starts the members of the hits a Memory limiter counts: they
// tell its hits from Valkey's (Owns).
const memoryMember = "mem-"

// Memory is a Limiter of this process only, with the semantics of the Valkey
// one (sliding window, all-or-none Reserve): the fallback of the rate limits
// while Valkey does not answer (internal/cache/fallback), and tests. It is
// safe for concurrent use.
//
// It holds at most DefaultMemoryKeys keys: when they are all in use, a
// reservation that needs a new key is refused, as if over its limit, rather
// than letting memory grow without bound.
type Memory struct {
	mu        sync.Mutex
	now       func() time.Time
	maxKeys   int
	keys      map[string]*memKey
	seq       uint64
	nextSweep time.Time
}

type memKey struct {
	hits   []memHit // oldest first
	window time.Duration
}

type memHit struct {
	at     time.Time
	member string
}

var _ Limiter = (*Memory)(nil)

// NewMemory returns an empty limiter. now may be nil (time.Now).
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{now: now, maxKeys: DefaultMemoryKeys, keys: map[string]*memKey{}}
}

// Owns tells whether h was counted by a Memory limiter.
func (m *Memory) Owns(h Hit) bool { return strings.HasPrefix(h.Member, memoryMember) }

func (m *Memory) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	res, err := m.Reserve(ctx, Rule{Key: key, Limit: limit, Window: window})
	return res.OK, err
}

func (m *Memory) Reserve(_ context.Context, rules ...Rule) (Reservation, error) {
	if len(rules) == 0 {
		return Reservation{OK: true}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if !now.Before(m.nextSweep) {
		m.sweep(now)
	}

	// Rule by rule, as the Valkey script: a key given twice sees its first
	// hit. Any refusal removes the hits counted before it.
	res := Reservation{OK: true}
	var counted []Hit
	for _, r := range rules {
		k := m.keys[r.Key]
		if k == nil {
			if len(m.keys) >= m.maxKeys {
				m.sweep(now)
			}
			if len(m.keys) >= m.maxKeys {
				res.OK = false
				res.RetryAfter = max(res.RetryAfter, time.Second)
				continue
			}
			k = &memKey{}
			m.keys[r.Key] = k
		}
		k.window = max(k.window, r.Window)
		k.prune(now, r.Window)
		count := int64(len(k.hits))
		if count < r.Limit {
			m.seq++
			h := memHit{at: now, member: memoryMember + strconv.FormatUint(m.seq, 10)}
			k.hits = append(k.hits, h)
			counted = append(counted, Hit{Key: r.Key, Member: h.member})
			continue
		}
		res.OK = false
		retry := r.Window
		if r.Limit > 0 {
			// The hit that keeps the count at the limit leaves the window then.
			retry = k.hits[count-r.Limit].at.Add(r.Window).Sub(now)
		}
		res.RetryAfter = max(res.RetryAfter, max(retry, 0))
	}
	if !res.OK {
		m.release(counted)
		return Reservation{RetryAfter: res.RetryAfter}, nil
	}
	res.Hits = counted
	return res, nil
}

func (m *Memory) Release(_ context.Context, hits ...Hit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.release(hits)
	return nil
}

func (m *Memory) release(hits []Hit) {
	for _, h := range hits {
		k := m.keys[h.Key]
		if k == nil {
			continue
		}
		for i, kh := range k.hits {
			if kh.member == h.Member {
				k.hits = append(k.hits[:i], k.hits[i+1:]...)
				break
			}
		}
		if len(k.hits) == 0 {
			delete(m.keys, h.Key)
		}
	}
}

// prune drops the hits that left the window (at or before now - window).
func (k *memKey) prune(now time.Time, window time.Duration) {
	limit := now.Add(-window)
	i := 0
	for i < len(k.hits) && !k.hits[i].at.After(limit) {
		i++
	}
	if i > 0 {
		k.hits = append(k.hits[:0], k.hits[i:]...)
	}
}

// sweep drops the keys whose hits all left the longest window they were
// used with. Caller holds mu.
func (m *Memory) sweep(now time.Time) {
	for key, k := range m.keys {
		k.prune(now, k.window)
		if len(k.hits) == 0 {
			delete(m.keys, key)
		}
	}
	m.nextSweep = now.Add(time.Minute)
}
