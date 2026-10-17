package mfastore_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"sso.internal/sso/internal/mfastore"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s := mfastore.NewMemory(func() time.Time { return now })

	if c, _ := s.GetChallenge(ctx, "k"); c != nil {
		t.Fatal("unknown key must return nil")
	}
	_ = s.SaveChallenge(ctx, "k", mfastore.LoginChallenge{UserID: "u1", Methods: []string{"totp"}}, time.Minute)
	c, _ := s.GetChallenge(ctx, "k")
	if c == nil || c.UserID != "u1" {
		t.Fatalf("got %+v", c)
	}
	for want := int64(1); want <= 3; want++ {
		if n, _ := s.IncrementAttempts(ctx, "k", time.Minute); n != want {
			t.Fatalf("attempts = %d, want %d", n, want)
		}
	}

	// Exactly one of many concurrent takers wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := s.TakeChallenge(ctx, "k"); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d takers won, want exactly 1", wins)
	}
	if c, _ := s.GetChallenge(ctx, "k"); c != nil {
		t.Fatal("a taken challenge is gone")
	}

	_ = s.SaveChallenge(ctx, "e", mfastore.LoginChallenge{UserID: "u2"}, time.Minute)
	now = now.Add(2 * time.Minute)
	if c, _ := s.GetChallenge(ctx, "e"); c != nil {
		t.Fatal("expired challenge must be gone")
	}
	if ok, _ := s.TakeChallenge(ctx, "e"); ok {
		t.Fatal("an expired challenge cannot be taken")
	}
}

func TestMemoryStore_Ceremony(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s := mfastore.NewMemory(func() time.Time { return now })

	_ = s.SaveCeremony(ctx, "register:s1", mfastore.Ceremony{Purpose: "register", UserID: "u1", SessionData: []byte(`{"challenge":"x"}`)}, time.Minute)
	c, _ := s.TakeCeremony(ctx, "register:s1")
	if c == nil || c.UserID != "u1" || string(c.SessionData) != `{"challenge":"x"}` {
		t.Fatalf("got %+v", c)
	}
	if c, _ := s.TakeCeremony(ctx, "register:s1"); c != nil {
		t.Fatal("a ceremony is single use")
	}

	_ = s.SaveCeremony(ctx, "login:k", mfastore.Ceremony{Purpose: "login"}, time.Minute)
	now = now.Add(2 * time.Minute)
	if c, _ := s.TakeCeremony(ctx, "login:k"); c != nil {
		t.Fatal("an expired ceremony is gone")
	}
}
