package valkey

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/cache/fallback"
)

// stubClient answers every command with err (nil: a value). Only the
// methods the guard calls are implemented.
type stubClient struct {
	valkey.Client
	mu    sync.Mutex
	err   error
	calls int
}

func (s *stubClient) set(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *stubClient) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubClient) Do(context.Context, valkey.Completed) valkey.ValkeyResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return valkey.NewErrorResult(s.err)
}

func (s *stubClient) DoMulti(_ context.Context, multi ...valkey.Completed) []valkey.ValkeyResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	out := make([]valkey.ValkeyResult, len(multi))
	for i := range out {
		out[i] = valkey.NewErrorResult(s.err)
	}
	return out
}

func (s *stubClient) Nodes() map[string]valkey.Client { return map[string]valkey.Client{"n1": s} }

func (s *stubClient) Close() {}

type guardTest struct {
	stub *stubClient
	c    valkey.Client
	g    *Guard
	now  time.Time
	logs *bytes.Buffer
}

func newGuardTest() *guardTest {
	gt := &guardTest{stub: &stubClient{}, now: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), logs: &bytes.Buffer{}}
	gt.c, gt.g = Guarded(gt.stub)
	gt.g.now = func() time.Time { return gt.now }
	gt.g.logger = slog.New(slog.NewTextHandler(gt.logs, nil))
	return gt
}

func (gt *guardTest) do(ctx context.Context) error {
	return gt.c.Do(ctx, valkey.Completed{}).Error()
}

var errRefused = errors.New("dial tcp 172.30.0.5:6379: connect: connection refused")

func TestGuardOutage(t *testing.T) {
	ctx := context.Background()
	gt := newGuardTest()

	if err := gt.do(ctx); err != nil || gt.g.Err() != nil {
		t.Fatalf("Valkey answers: %v, %v", err, gt.g.Err())
	}

	gt.stub.set(errRefused)
	err := gt.do(ctx)
	if !errors.Is(err, fallback.ErrUnavailable) || !errors.Is(err, errRefused) {
		t.Fatalf("a network error is marked unavailable and keeps its cause: %v", err)
	}
	if !errors.Is(gt.g.Err(), fallback.ErrUnavailable) {
		t.Fatal("down")
	}
	if !strings.Contains(gt.logs.String(), "level=ERROR") || !strings.Contains(gt.logs.String(), "degraded mode") {
		t.Fatalf("the start of an outage is an error in the log: %s", gt.logs)
	}

	// The commands that follow fail at once, without the network.
	calls := gt.stub.count()
	for range 5 {
		if err := gt.do(ctx); !errors.Is(err, fallback.ErrUnavailable) {
			t.Fatalf("during the outage: %v", err)
		}
	}
	if gt.stub.count() != calls {
		t.Fatal("no command may reach Valkey before the next probe")
	}

	// One probe per interval; a failed one waits for the next.
	gt.now = gt.now.Add(probeInterval)
	_ = gt.do(ctx)
	if gt.stub.count() != calls+1 {
		t.Fatal("the probe goes to Valkey")
	}
	_ = gt.do(ctx)
	if gt.stub.count() != calls+1 {
		t.Fatal("after a failed probe, the next waits for the interval")
	}

	// Reminder in the log while it lasts.
	gt.logs.Reset()
	gt.now = gt.now.Add(reminderInterval)
	_ = gt.do(ctx)
	if !strings.Contains(gt.logs.String(), "still unreachable") {
		t.Fatalf("a reminder every %s: %s", reminderInterval, gt.logs)
	}

	// Valkey is back: the next probe ends the outage.
	gt.stub.set(nil)
	gt.now = gt.now.Add(probeInterval)
	if err := gt.do(ctx); err != nil {
		t.Fatalf("the probe gets an answer: %v", err)
	}
	if gt.g.Err() != nil {
		t.Fatal("up again")
	}
	if !strings.Contains(gt.logs.String(), "reachable again") {
		t.Fatalf("the end of an outage is logged: %s", gt.logs)
	}
	if err := gt.do(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGuardOneProbeAtATime(t *testing.T) {
	gt := newGuardTest()
	gt.stub.set(errRefused)
	_ = gt.do(context.Background())
	gt.now = gt.now.Add(probeInterval)

	probe, err := gt.g.admit()
	if !probe || err != nil {
		t.Fatalf("the first command after the interval probes: %v, %v", probe, err)
	}
	if probe2, err := gt.g.admit(); probe2 || !errors.Is(err, fallback.ErrUnavailable) {
		t.Fatal("a probe is running: the others fail at once")
	}
	gt.g.done(context.Background(), true, unknown, nil) // the probe's caller gave up
	if gt.g.Err() == nil {
		t.Fatal("a probe that learnt nothing does not end the outage")
	}
	if probe3, _ := gt.g.admit(); !probe3 {
		t.Fatal("another command may probe at once")
	}
}

func TestGuardWhatIsAnOutage(t *testing.T) {
	gt := newGuardTest()

	// The caller gave up: says nothing of Valkey.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gt.stub.set(context.Canceled)
	if err := gt.do(ctx); !errors.Is(err, context.Canceled) || errors.Is(err, fallback.ErrUnavailable) {
		t.Fatalf("cancelled: %v", err)
	}
	if gt.g.Err() != nil {
		t.Fatal("a cancelled request is not an outage")
	}

	// A deadline that Valkey made us miss is one.
	gt.stub.set(context.DeadlineExceeded)
	if err := gt.do(context.Background()); !errors.Is(err, fallback.ErrUnavailable) {
		t.Fatalf("timed out: %v", err)
	}
	gt.stub.set(nil)
	gt.now = gt.now.Add(probeInterval)
	_ = gt.do(context.Background())

	// "nil" (no such key) is an answer.
	gt.stub.set(valkey.Nil)
	if err := gt.do(context.Background()); !valkey.IsValkeyNil(err) || gt.g.Err() != nil {
		t.Fatalf("a missing key: %v", err)
	}

	// ErrClosing: an outage, unless we closed the client ourselves.
	gt.stub.set(valkey.ErrClosing)
	if err := gt.do(context.Background()); !errors.Is(err, fallback.ErrUnavailable) {
		t.Fatalf("a connection given up: %v", err)
	}
	gt2 := newGuardTest()
	gt2.c.Close()
	gt2.stub.set(valkey.ErrClosing)
	if err := gt2.do(context.Background()); errors.Is(err, fallback.ErrUnavailable) || gt2.g.Err() != nil {
		t.Fatalf("after Close: %v", err)
	}
}

func TestGuardDoMultiAndNodes(t *testing.T) {
	ctx := context.Background()
	gt := newGuardTest()
	gt.stub.set(errRefused)
	res := gt.c.DoMulti(ctx, valkey.Completed{}, valkey.Completed{})
	for i, r := range res {
		if !errors.Is(r.Error(), fallback.ErrUnavailable) {
			t.Fatalf("result %d: %v", i, r.Error())
		}
	}
	if gt.g.Err() == nil {
		t.Fatal("down")
	}
	calls := gt.stub.count()
	res = gt.c.DoMulti(ctx, valkey.Completed{})
	if !errors.Is(res[0].Error(), fallback.ErrUnavailable) || gt.stub.count() != calls {
		t.Fatal("DoMulti fails at once during the outage")
	}
	// Lua.ExecMulti loads its scripts through Nodes: guarded too.
	for _, n := range gt.c.Nodes() {
		if err := n.Do(ctx, valkey.Completed{}).Error(); !errors.Is(err, fallback.ErrUnavailable) || gt.stub.count() != calls {
			t.Fatalf("a node fails at once too: %v", err)
		}
	}
}

// valkey-go retries a read until its context ends, and a request's has no
// deadline: during an outage it would never return (nor reach the Guard).
func TestRetriesAreBounded(t *testing.T) {
	for attempts, want := range map[int]time.Duration{1: 50 * time.Millisecond, 2: 100 * time.Millisecond} {
		if got := retryDelay(attempts, valkey.Completed{}, errRefused); got != want {
			t.Errorf("attempt %d: %s, want %s", attempts, got, want)
		}
	}
	if got := retryDelay(maxRetries+1, valkey.Completed{}, errRefused); got >= 0 {
		t.Fatalf("after %d retries, no more: %s", maxRetries, got)
	}
}
