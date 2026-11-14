package valkey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/cache/fallback"
)

const (
	// probeInterval: while Valkey is down, one command that often tries it
	// again; the others fail at once.
	probeInterval = 2 * time.Second
	// reminderInterval: while Valkey is down, the log says so again that
	// often (an alert on the log keeps firing).
	reminderInterval = 5 * time.Minute
)

// Guard watches whether Valkey answers, for a client made by Guarded.
//
// When a command fails because Valkey cannot be reached (connection refused,
// lost or timed out, as opposed to an error the server answered), Valkey is
// down: the commands that follow fail at once with an error wrapping
// fallback.ErrUnavailable, instead of each waiting for the network, and the
// stores of internal/cache/fallback carry on in memory. One command every
// probeInterval still tries Valkey; the first that gets an answer ends the
// outage. Start and end of an outage are logged (error, then info), and a
// reminder every reminderInterval while it lasts.
type Guard struct {
	now    func() time.Time
	logger *slog.Logger

	mu           sync.Mutex
	down         bool
	since        time.Time // start of the outage
	cause        error     // last network error
	nextProbe    time.Time
	probing      bool
	nextReminder time.Time
	closed       bool // Close was called: ErrClosing is not an outage
}

// Guarded wraps c: see Guard.
func Guarded(c valkey.Client) (valkey.Client, *Guard) {
	g := &Guard{now: time.Now, logger: slog.Default()}
	return &guardedClient{Client: c, g: g}, g
}

// Err is nil while Valkey answers; during an outage, an error wrapping
// fallback.ErrUnavailable that says since when and why.
func (g *Guard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.down {
		return nil
	}
	return g.unavailable()
}

// unavailable is the error of a command refused during an outage. Caller
// holds mu.
func (g *Guard) unavailable() error {
	return fmt.Errorf("%w since %s (sign-ins go on in degraded mode, state kept in memory): %v",
		fallback.ErrUnavailable, g.since.UTC().Format(time.RFC3339), g.cause)
}

// admit tells whether a command may go to Valkey, and whether it is the
// probe of an outage. It returns the error to answer otherwise.
func (g *Guard) admit() (probe bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.down {
		return false, nil
	}
	if g.probing || g.now().Before(g.nextProbe) {
		return false, g.unavailable()
	}
	g.probing = true
	return true, nil
}

// outcome of a command that went to Valkey.
type outcome int

const (
	answered    outcome = iota // Valkey answered (a value, nil, or an error of its own)
	unreachable                // Valkey could not be reached
	unknown                    // nothing learnt: the caller gave up, or we closed the client
)

// classify tells what err says of Valkey.
func (g *Guard) classify(ctx context.Context, err error) outcome {
	if err == nil || valkey.IsValkeyNil(err) {
		return answered
	}
	if ve, ok := valkey.IsValkeyErr(err); ok {
		// The server answered. Still down for a command while it loads its
		// data after a restart, or has no master to write to (failover).
		msg := ve.Error()
		if ve.IsLoading() || ve.IsClusterDown() || ve.IsTryAgain() ||
			strings.HasPrefix(msg, "MASTERDOWN") || strings.HasPrefix(msg, "READONLY") {
			return unreachable
		}
		return answered
	}
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return unknown // the caller gave up (browser gone)
	}
	if errors.Is(err, valkey.ErrClosing) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.closed {
			return unknown // closed by us at shutdown
		}
		return unreachable // a connection the client gave up
	}
	return unreachable // network: refused, reset, timed out (a deadline too), DNS
}

// done records how a command that went to Valkey ended; cause is the error
// when unreachable. probe: the command was the probe of an outage.
func (g *Guard) done(ctx context.Context, probe bool, o outcome, cause error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if probe {
		g.probing = false
	}
	switch o {
	case unknown:
		return
	case answered:
		if g.down {
			g.down = false
			g.logger.InfoContext(ctx, "valkey: reachable again, degraded mode ended",
				"outage", now.Sub(g.since).Round(time.Second).String())
		}
		return
	}
	g.cause = cause
	g.nextProbe = now.Add(probeInterval)
	if !g.down {
		g.down, g.since = true, now
		g.nextReminder = now.Add(reminderInterval)
		g.logger.ErrorContext(ctx, "valkey: unreachable, degraded mode: rate limits, lockout counters, "+
			"MFA challenges and OIDC/SAML flows are kept in this server's memory until it answers again", "error", cause)
		return
	}
	if !now.Before(g.nextReminder) {
		g.nextReminder = now.Add(reminderInterval)
		g.logger.ErrorContext(ctx, "valkey: still unreachable, degraded mode",
			"since", g.since.UTC().Format(time.RFC3339), "error", cause)
	}
}

// markUnavailable wraps a network error so that errors.Is finds both
// fallback.ErrUnavailable and the error itself.
type markUnavailable struct{ err error }

func (e markUnavailable) Error() string   { return "valkey unavailable: " + e.err.Error() }
func (e markUnavailable) Unwrap() []error { return []error{fallback.ErrUnavailable, e.err} }

// guardedClient is a valkey.Client whose commands go through a Guard. The
// methods this code base does not use (DoCache, DoStream, Receive,
// Dedicated...) go to the client unguarded.
type guardedClient struct {
	valkey.Client
	g *Guard
}

func (c *guardedClient) Do(ctx context.Context, cmd valkey.Completed) valkey.ValkeyResult {
	probe, err := c.g.admit()
	if err != nil {
		return valkey.NewErrorResult(err)
	}
	res := c.Client.Do(ctx, cmd)
	err = res.Error()
	o := c.g.classify(ctx, err)
	c.g.done(ctx, probe, o, err)
	if o == unreachable {
		return valkey.NewErrorResult(markUnavailable{err})
	}
	return res
}

func (c *guardedClient) DoMulti(ctx context.Context, multi ...valkey.Completed) []valkey.ValkeyResult {
	probe, err := c.g.admit()
	if err != nil {
		out := make([]valkey.ValkeyResult, len(multi))
		for i := range out {
			out[i] = valkey.NewErrorResult(err)
		}
		return out
	}
	res := c.Client.DoMulti(ctx, multi...)
	// Unreachable if one command was; answered only if every one was.
	all, cause := answered, error(nil)
	for i, r := range res {
		err := r.Error()
		switch c.g.classify(ctx, err) {
		case unreachable:
			if cause == nil {
				all, cause = unreachable, err
			}
			res[i] = valkey.NewErrorResult(markUnavailable{err})
		case unknown:
			if all == answered {
				all = unknown
			}
		}
	}
	c.g.done(ctx, probe, all, cause)
	return res
}

// Nodes are guarded too: Lua.ExecMulti loads its script through them.
func (c *guardedClient) Nodes() map[string]valkey.Client {
	nodes := c.Client.Nodes()
	out := make(map[string]valkey.Client, len(nodes))
	for addr, n := range nodes {
		out[addr] = &guardedClient{Client: n, g: c.g}
	}
	return out
}

func (c *guardedClient) Close() {
	c.g.mu.Lock()
	c.g.closed = true
	c.g.mu.Unlock()
	c.Client.Close()
}
