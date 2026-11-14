package ratelimit

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)} }

func TestMemorySlidingWindow(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := NewMemory(c.now)
	rule := Rule{Key: "k", Limit: 3, Window: time.Minute}

	for i := range 3 {
		res, err := m.Reserve(ctx, rule)
		if err != nil || !res.OK || len(res.Hits) != 1 {
			t.Fatalf("hit %d: %+v, %v", i+1, res, err)
		}
		if !m.Owns(res.Hits[0]) || m.Owns(Hit{Key: "k", Member: "1700000000-abcd"}) {
			t.Fatal("Owns must tell its hits from Valkey's")
		}
		c.add(10 * time.Second)
	}
	// Hits at 0s, 10s, 20s; now 30s: the first leaves the window at 60s.
	res, err := m.Reserve(ctx, rule)
	if err != nil || res.OK || res.RetryAfter != 30*time.Second || len(res.Hits) != 0 {
		t.Fatalf("over the limit: %+v, %v", res, err)
	}
	c.add(30 * time.Second) // 60s: the hit of 0s is out (at or before now - window)
	if ok, _ := m.Allow(ctx, "k", 3, time.Minute); !ok {
		t.Fatal("the window slid: one hit must be free")
	}
	if ok, _ := m.Allow(ctx, "k", 3, time.Minute); ok {
		t.Fatal("full again")
	}
	if ok, _ := m.Allow(ctx, "other", 3, time.Minute); !ok {
		t.Fatal("keys are counted apart")
	}
}

func TestMemoryAllOrNone(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := NewMemory(c.now)
	full := Rule{Key: "full", Limit: 1, Window: time.Minute}
	if ok, _ := m.Allow(ctx, full.Key, full.Limit, full.Window); !ok {
		t.Fatal("first hit")
	}
	free := Rule{Key: "free", Limit: 1, Window: time.Minute}
	if res, _ := m.Reserve(ctx, free, full); res.OK {
		t.Fatal("one rule has no room: refused")
	}
	if res, _ := m.Reserve(ctx, free); !res.OK {
		t.Fatal("the hit counted under free by the refused reservation must be given back")
	}

	// A key given twice sees its first hit, as in the Valkey script.
	if res, _ := m.Reserve(ctx, Rule{Key: "twice", Limit: 1, Window: time.Minute}, Rule{Key: "twice", Limit: 1, Window: time.Minute}); res.OK {
		t.Fatal("the same key twice with a limit of 1: refused")
	}
	if res, _ := m.Reserve(ctx, Rule{Key: "zero", Limit: 0, Window: time.Minute}); res.OK || res.RetryAfter != time.Minute {
		t.Fatalf("a limit of 0 refuses, retry after the window: %+v", res)
	}
}

func TestMemoryRelease(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(newClock().now)
	rule := Rule{Key: "k", Limit: 1, Window: time.Hour}
	res, _ := m.Reserve(ctx, rule)
	if !res.OK {
		t.Fatal("first hit")
	}
	if again, _ := m.Reserve(ctx, rule); again.OK {
		t.Fatal("full")
	}
	if err := m.Release(ctx, res.Hits...); err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Reserve(ctx, rule); !again.OK {
		t.Fatal("released: room again")
	}
	if err := m.Release(ctx, Hit{Key: "unknown", Member: "mem-999"}); err != nil {
		t.Fatal("releasing a hit it does not hold is harmless")
	}
}

func TestMemoryBounded(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := NewMemory(c.now)
	m.maxKeys = 3
	for i := range 3 {
		if ok, _ := m.Allow(ctx, "k"+strconv.Itoa(i), 5, time.Minute); !ok {
			t.Fatalf("key %d", i)
		}
	}
	res, err := m.Reserve(ctx, Rule{Key: "k3", Limit: 5, Window: time.Minute})
	if err != nil || res.OK || res.RetryAfter <= 0 {
		t.Fatalf("full: a new key is refused, %+v, %v", res, err)
	}
	if ok, _ := m.Allow(ctx, "k0", 5, time.Minute); !ok {
		t.Fatal("a key it holds still counts")
	}
	c.add(2 * time.Minute) // every hit left its window: swept on demand
	if ok, _ := m.Allow(ctx, "k3", 5, time.Minute); !ok {
		t.Fatal("expired keys make room")
	}
	if len(m.keys) != 1 {
		t.Fatalf("the expired keys must be gone, %d left", len(m.keys))
	}
}

func TestMemoryConcurrent(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for range 50 {
		wg.Go(func() {
			if ok, _ := m.Allow(ctx, "k", 10, time.Minute); ok {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if passed != 10 {
		t.Fatalf("%d of 50 concurrent requests passed a limit of 10", passed)
	}
}
