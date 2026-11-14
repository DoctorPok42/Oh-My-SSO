package fallback

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/lockoutstore"
	"sso.internal/sso/internal/mfastore"
	"sso.internal/sso/internal/oidcstore"
	"sso.internal/sso/internal/ratelimit"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)} }

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

// outage is the state of the fake Valkey: up, down (ErrUnavailable), or
// answering another error.
type outage struct {
	down  atomic.Bool
	other atomic.Pointer[error]
	calls atomic.Int64
}

var errRefused = errors.New("NOPERM this user has no permissions to run the 'evalsha' command")

func (o *outage) err() error {
	o.calls.Add(1)
	if o.down.Load() {
		return fmt.Errorf("oidcstore: get: %w", markUnavailable(errors.New("dial tcp: connection refused")))
	}
	if e := o.other.Load(); e != nil {
		return *e
	}
	return nil
}

// markUnavailable stands for the Valkey client's wrapping.
func markUnavailable(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }

// --- the stores of Valkey, as memory behind a switch ---

type fakeFlows struct {
	*outage
	mem *oidcstore.Memory
}

func (f fakeFlows) Put(ctx context.Context, k string, v []byte, ttl time.Duration) error {
	if err := f.err(); err != nil {
		return err
	}
	return f.mem.Put(ctx, k, v, ttl)
}

func (f fakeFlows) PutIfAbsent(ctx context.Context, k string, v []byte, ttl time.Duration) (bool, error) {
	if err := f.err(); err != nil {
		return false, err
	}
	return f.mem.PutIfAbsent(ctx, k, v, ttl)
}

func (f fakeFlows) Get(ctx context.Context, k string) ([]byte, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.mem.Get(ctx, k)
}

func (f fakeFlows) Take(ctx context.Context, k string) ([]byte, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.mem.Take(ctx, k)
}

func (f fakeFlows) Delete(ctx context.Context, k string) error {
	if err := f.err(); err != nil {
		return err
	}
	return f.mem.Delete(ctx, k)
}

func newFlows(t *testing.T) (*FlowStore, *outage, *oidcstore.Memory, *clock) {
	t.Helper()
	c := newClock()
	o := &outage{}
	mem := oidcstore.NewMemory(c.now)
	return NewFlowStore(fakeFlows{o, mem}, c.now), o, mem, c
}

func mustGet(t *testing.T, s oidcstore.Store, key, want string) {
	t.Helper()
	got, err := s.Get(context.Background(), key)
	if err != nil || string(got) != want {
		t.Fatalf("Get(%q) = %q, %v; want %q", key, got, err, want)
	}
}

func TestFlowStoreValkeyUp(t *testing.T) {
	ctx := context.Background()
	s, _, valkey, _ := newFlows(t)
	if err := s.Put(ctx, "ar", []byte("v1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	mustGet(t, valkey, "ar", "v1")
	if len(s.items.items) != 0 {
		t.Fatal("while Valkey answers, memory holds nothing")
	}
	mustGet(t, s, "ar", "v1")
	if v, _ := s.Take(ctx, "ar"); string(v) != "v1" {
		t.Fatal("take from Valkey")
	}
	if v, _ := s.Take(ctx, "ar"); v != nil {
		t.Fatal("taken once")
	}
}

func TestFlowStoreDuringAnOutage(t *testing.T) {
	ctx := context.Background()
	s, o, valkey, _ := newFlows(t)
	if err := s.Put(ctx, "before", []byte("old"), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	o.down.Store(true)

	// A flow started during the outage works from memory.
	if err := s.Put(ctx, "ar", []byte("v1"), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	mustGet(t, s, "ar", "v1")
	first, err := s.PutIfAbsent(ctx, "ar:code", []byte("h"), 10*time.Minute)
	if err != nil || !first {
		t.Fatalf("first code: %v, %v", first, err)
	}
	if again, _ := s.PutIfAbsent(ctx, "ar:code", []byte("h2"), 10*time.Minute); again {
		t.Fatal("one code per request, in memory too")
	}
	if err := s.Put(ctx, "code", []byte("ar"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Take(ctx, "code"); string(v) != "ar" {
		t.Fatal("the code is taken from memory")
	}
	if v, _ := s.Take(ctx, "code"); v != nil {
		t.Fatal("a code is taken once")
	}

	// What Valkey held before the outage cannot be read: closed.
	if _, err := s.Get(ctx, "before"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get of a key in Valkey during an outage: %v", err)
	}
	if _, err := s.Take(ctx, "before"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Take of a key in Valkey during an outage: %v", err)
	}

	// Valkey is back: the flow started during the outage goes on.
	o.down.Store(false)
	mustGet(t, s, "ar", "v1")
	if again, _ := s.PutIfAbsent(ctx, "ar:code", []byte("h3"), 10*time.Minute); again {
		t.Fatal("memory still holds the code marker: Valkey must not be asked")
	}
	if v, _ := valkey.Get(ctx, "ar"); v != nil {
		t.Fatal("nothing of the outage is copied to Valkey")
	}
	mustGet(t, s, "before", "old")
}

func TestFlowStoreTombstones(t *testing.T) {
	ctx := context.Background()
	s, o, valkey, c := newFlows(t)
	// An authorization request in Valkey, then updated during an outage.
	if err := s.Put(ctx, "ar", []byte("not signed in"), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	o.down.Store(true)
	if err := s.Put(ctx, "ar", []byte("signed in"), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	mustGet(t, s, "ar", "signed in")
	if err := s.Delete(ctx, "ar"); err != nil {
		t.Fatal("deleting during an outage succeeds:", err)
	}
	o.down.Store(false)
	// Valkey still holds the first version: it must not come back.
	mustGet(t, valkey, "ar", "not signed in")
	mustGet(t, s, "ar", "")
	if v, _ := s.Take(ctx, "ar"); v != nil {
		t.Fatal("a deleted key is not taken")
	}

	// A key only Valkey holds, deleted while Valkey is down.
	if err := s.Put(ctx, "pending", []byte("p"), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	o.down.Store(true)
	if err := s.Delete(ctx, "pending"); err != nil {
		t.Fatal(err)
	}
	o.down.Store(false)
	mustGet(t, s, "pending", "")
	// It may be written again (PutIfAbsent sees it absent), in memory.
	if first, _ := s.PutIfAbsent(ctx, "pending", []byte("p2"), 10*time.Minute); !first {
		t.Fatal("a deleted key is absent")
	}
	mustGet(t, s, "pending", "p2")

	// The tombstones outlive Valkey's copies, then go.
	c.add(16 * time.Minute)
	mustGet(t, valkey, "ar", "")
	mustGet(t, s, "ar", "") // the expired tombstone is dropped, Valkey answers
	if _, ok := s.items.items["ar"]; ok {
		t.Fatal("an expired entry is dropped when read")
	}
	o.down.Store(true)
	if err := s.Put(ctx, "x", []byte("y"), time.Minute); err != nil { // a write to memory sweeps
		t.Fatal(err)
	}
	if len(s.items.items) != 1 {
		t.Fatalf("the expired entries are swept: %d left", len(s.items.items))
	}
}

func TestFlowStoreOtherErrors(t *testing.T) {
	ctx := context.Background()
	s, o, _, _ := newFlows(t)
	o.other.Store(&errRefused)
	if err := s.Put(ctx, "k", []byte("v"), time.Minute); !errors.Is(err, errRefused) {
		t.Fatalf("an error of Valkey's own is returned: %v", err)
	}
	if _, err := s.PutIfAbsent(ctx, "k", []byte("v"), time.Minute); !errors.Is(err, errRefused) {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, errRefused) {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.items.items) != 0 {
		t.Fatal("no fallback on a refusal")
	}
}

func TestFlowStoreConcurrentFirst(t *testing.T) {
	ctx := context.Background()
	s, o, _, _ := newFlows(t)
	o.down.Store(true)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if first, _ := s.PutIfAbsent(ctx, "marker", []byte{1}, time.Minute); first {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d calls were first", wins.Load())
	}
}

func TestTTLMapBounded(t *testing.T) {
	c := newClock()
	m := newTTLMap[int](c.now, 2)
	if m.set("a", 1, time.Minute) != nil || m.set("b", 2, 2*time.Minute) != nil {
		t.Fatal("room for two")
	}
	if !errors.Is(m.set("c", 3, time.Minute), errFull) {
		t.Fatal("a third key is refused")
	}
	if m.set("a", 10, time.Minute) != nil {
		t.Fatal("a key it holds can always be written")
	}
	c.add(90 * time.Second) // a expired, b not
	if m.set("c", 3, time.Minute) != nil {
		t.Fatal("an expired entry makes room")
	}
	if _, ok := m.get("a"); ok {
		t.Fatal("expired")
	}
	if v, ok := m.get("b"); !ok || v != 2 {
		t.Fatal("b lives")
	}
}

// --- MFA ---

type fakeMFA struct {
	*outage
	mem *mfastore.Memory
}

func (f fakeMFA) SaveChallenge(ctx context.Context, k string, c mfastore.LoginChallenge, ttl time.Duration) error {
	if err := f.err(); err != nil {
		return err
	}
	return f.mem.SaveChallenge(ctx, k, c, ttl)
}

func (f fakeMFA) GetChallenge(ctx context.Context, k string) (*mfastore.LoginChallenge, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.mem.GetChallenge(ctx, k)
}

func (f fakeMFA) IncrementAttempts(ctx context.Context, k string, ttl time.Duration) (int64, error) {
	if err := f.err(); err != nil {
		return 0, err
	}
	return f.mem.IncrementAttempts(ctx, k, ttl)
}

func (f fakeMFA) TakeChallenge(ctx context.Context, k string) (bool, error) {
	if err := f.err(); err != nil {
		return false, err
	}
	return f.mem.TakeChallenge(ctx, k)
}

func (f fakeMFA) SaveCeremony(ctx context.Context, k string, c mfastore.Ceremony, ttl time.Duration) error {
	if err := f.err(); err != nil {
		return err
	}
	return f.mem.SaveCeremony(ctx, k, c, ttl)
}

func (f fakeMFA) TakeCeremony(ctx context.Context, k string) (*mfastore.Ceremony, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return f.mem.TakeCeremony(ctx, k)
}

func TestMFAStoreDuringAnOutage(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	o := &outage{}
	valkey := mfastore.NewMemory(c.now)
	s := NewMFAStore(fakeMFA{o, valkey}, c.now)

	if err := s.SaveChallenge(ctx, "before", mfastore.LoginChallenge{UserID: "u0"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	o.down.Store(true)
	if err := s.SaveChallenge(ctx, "ch", mfastore.LoginChallenge{UserID: "u1"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetChallenge(ctx, "ch"); err != nil || got == nil || got.UserID != "u1" {
		t.Fatalf("challenge from memory: %+v, %v", got, err)
	}
	for want := int64(1); want <= 3; want++ {
		if n, err := s.IncrementAttempts(ctx, "ch", 5*time.Minute); err != nil || n != want {
			t.Fatalf("attempt %d: %d, %v", want, n, err)
		}
	}

	// A challenge of before the outage: every call fails, nothing is guessed.
	if _, err := s.GetChallenge(ctx, "before"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetChallenge: %v", err)
	}
	if _, err := s.IncrementAttempts(ctx, "before", time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("IncrementAttempts must not start a fresh count in memory: %v", err)
	}
	if _, err := s.TakeChallenge(ctx, "before"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("TakeChallenge: %v", err)
	}

	// Valkey is back: the attempts go on counting where the challenge is.
	o.down.Store(false)
	if n, _ := s.IncrementAttempts(ctx, "ch", 5*time.Minute); n != 4 {
		t.Fatalf("attempts after the outage: %d, want 4", n)
	}
	if taken, _ := s.TakeChallenge(ctx, "ch"); !taken {
		t.Fatal("taken")
	}
	if taken, _ := s.TakeChallenge(ctx, "ch"); taken {
		t.Fatal("taken once")
	}
	if got, _ := s.GetChallenge(ctx, "ch"); got != nil {
		t.Fatal("gone")
	}
}

func TestMFAStoreCeremonies(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	o := &outage{}
	valkey := mfastore.NewMemory(c.now)
	s := NewMFAStore(fakeMFA{o, valkey}, c.now)

	// A registration started before the outage, started again during it.
	if err := s.SaveCeremony(ctx, "reg:s1", mfastore.Ceremony{Purpose: "register", Name: "old"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	o.down.Store(true)
	if err := s.SaveCeremony(ctx, "reg:s1", mfastore.Ceremony{Purpose: "register", Name: "new"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	o.down.Store(false)
	got, err := s.TakeCeremony(ctx, "reg:s1")
	if err != nil || got == nil || got.Name != "new" {
		t.Fatalf("the latest ceremony, from memory: %+v, %v", got, err)
	}
	if got, _ := s.TakeCeremony(ctx, "reg:s1"); got != nil {
		t.Fatalf("taken: the older one Valkey holds must not come back, got %+v", got)
	}
	if err := s.SaveCeremony(ctx, "reg:s2", mfastore.Ceremony{Purpose: "register"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, _ := valkey.TakeCeremony(ctx, "reg:s2"); got == nil {
		t.Fatal("while Valkey answers, new ceremonies go there")
	}
}

// --- lockout ---

type fakeLockout struct {
	*outage
	mem *lockoutstore.Memory
}

func (f fakeLockout) Get(ctx context.Context, k string) (domain.LockoutState, error) {
	if err := f.err(); err != nil {
		return domain.LockoutState{}, err
	}
	return f.mem.Get(ctx, k)
}

func (f fakeLockout) CompareAndSwap(ctx context.Context, k string, old, next domain.LockoutState, ttl time.Duration) (bool, error) {
	if err := f.err(); err != nil {
		return false, err
	}
	return f.mem.CompareAndSwap(ctx, k, old, next, ttl)
}

func TestLockoutStoreDuringAnOutage(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	o := &outage{}
	valkey := lockoutstore.NewMemory(c.now)
	s := NewLockoutStore(fakeLockout{o, valkey}, c.now)
	at := c.now()

	two := domain.LockoutState{FailedCount: 2, LastFailedAt: at}
	if ok, err := s.CompareAndSwap(ctx, "k", domain.LockoutState{}, two, time.Hour); !ok || err != nil {
		t.Fatalf("in Valkey: %v, %v", ok, err)
	}

	o.down.Store(true)
	st, err := s.Get(ctx, "k")
	if err != nil || !st.IsZero() {
		t.Fatalf("during an outage, counters start from zero in memory: %+v, %v", st, err)
	}
	one := domain.LockoutState{FailedCount: 1, LastFailedAt: at}
	if ok, err := s.CompareAndSwap(ctx, "k", st, one, time.Hour); !ok || err != nil {
		t.Fatalf("swap in memory: %v, %v", ok, err)
	}
	if ok, _ := s.CompareAndSwap(ctx, "k", st, one, time.Hour); ok {
		t.Fatal("compare-and-swap holds in memory: the old state changed")
	}
	if st, _ := s.Get(ctx, "k"); st.FailedCount != 1 {
		t.Fatalf("memory: %+v", st)
	}

	o.down.Store(false)
	if st, _ := s.Get(ctx, "k"); st.FailedCount != 2 {
		t.Fatalf("Valkey's counter is used again: %+v", st)
	}
	// A swap prepared from memory's state does not apply to Valkey's.
	if ok, _ := s.CompareAndSwap(ctx, "k", one, domain.LockoutState{}, time.Hour); ok {
		t.Fatal("old does not match Valkey's state")
	}

	o.other.Store(&errRefused)
	if _, err := s.Get(ctx, "k"); !errors.Is(err, errRefused) {
		t.Fatalf("an error of Valkey's own is returned: %v", err)
	}
}

// --- rate limits ---

type fakeLimiter struct {
	*outage
	mem *ratelimit.Memory
}

func (f fakeLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	if err := f.err(); err != nil {
		return false, err
	}
	return f.mem.Allow(ctx, key, limit, window)
}

func (f fakeLimiter) Reserve(ctx context.Context, rules ...ratelimit.Rule) (ratelimit.Reservation, error) {
	if err := f.err(); err != nil {
		return ratelimit.Reservation{}, err
	}
	res, err := f.mem.Reserve(ctx, rules...)
	for i := range res.Hits {
		res.Hits[i].Member = "valkey-" + strconv.Itoa(i) + "-" + res.Hits[i].Member // not a memory member
	}
	return res, err
}

func (f fakeLimiter) Release(ctx context.Context, hits ...ratelimit.Hit) error {
	if len(hits) == 0 {
		return nil
	}
	if err := f.err(); err != nil {
		return err
	}
	return nil
}

func TestLimiterDuringAnOutage(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	o := &outage{}
	l := NewLimiter(fakeLimiter{o, ratelimit.NewMemory(c.now)}, c.now)
	rule := ratelimit.Rule{Key: "login:r:ip:1.2.3.4", Limit: 2, Window: time.Minute}

	res, err := l.Reserve(ctx, rule)
	if err != nil || !res.OK || l.local.Owns(res.Hits[0]) {
		t.Fatalf("Valkey counts while it answers: %+v, %v", res, err)
	}

	o.down.Store(true)
	for i := range 2 {
		if res, err = l.Reserve(ctx, rule); err != nil || !res.OK {
			t.Fatalf("hit %d in memory: %+v, %v", i+1, res, err)
		}
	}
	if !l.local.Owns(res.Hits[0]) {
		t.Fatal("a hit of memory")
	}
	if over, _ := l.Reserve(ctx, rule); over.OK || over.RetryAfter <= 0 {
		t.Fatalf("the limit holds in memory: %+v", over)
	}
	calls := o.calls.Load()
	if err := l.Release(ctx, res.Hits...); err != nil {
		t.Fatalf("a hit of memory is given back to memory: %v", err)
	}
	if o.calls.Load() != calls {
		t.Fatal("releasing memory's hits must not ask Valkey")
	}
	if ok, _ := l.Allow(ctx, rule.Key, rule.Limit, rule.Window); !ok {
		t.Fatal("released: room again")
	}

	o.down.Store(false)
	o.other.Store(&errRefused)
	if _, err := l.Reserve(ctx, rule); !errors.Is(err, errRefused) {
		t.Fatalf("an error of Valkey's own is returned, not hidden by memory: %v", err)
	}
}
