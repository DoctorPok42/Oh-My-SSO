package oidcstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemory(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	m := NewMemory(func() time.Time { return now })

	if v, err := m.Get(ctx, "k"); v != nil || err != nil {
		t.Fatalf("missing key: got %q, %v", v, err)
	}
	if err := m.Put(ctx, "k", []byte("v1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.PutIfAbsent(ctx, "k", []byte("v2"), time.Minute); ok {
		t.Fatal("PutIfAbsent overwrote an existing key")
	}
	if v, _ := m.Get(ctx, "k"); string(v) != "v1" {
		t.Fatalf("got %q", v)
	}
	if v, _ := m.Take(ctx, "k"); string(v) != "v1" {
		t.Fatalf("take: got %q", v)
	}
	if v, _ := m.Take(ctx, "k"); v != nil {
		t.Fatal("a value was taken twice")
	}

	_ = m.Put(ctx, "e", []byte("x"), time.Minute)
	now = now.Add(time.Minute)
	if v, _ := m.Get(ctx, "e"); v != nil {
		t.Fatal("expired value still readable")
	}
	if ok, _ := m.PutIfAbsent(ctx, "e", []byte("y"), time.Minute); !ok {
		t.Fatal("PutIfAbsent refused an expired key")
	}
}

func TestMemory_TakeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	m := NewMemory(nil)
	_ = m.Put(ctx, "code", []byte("req"), time.Minute)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, _ := m.Take(ctx, "code"); v != nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d goroutines took the same value, want 1", wins.Load())
	}
}
