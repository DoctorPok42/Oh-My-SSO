// Package fallback keeps the short-lived state of sign-ins in this server's
// memory while Valkey does not answer: rate limits, lockout counters of
// unknown identifiers and of devices, MFA challenges and WebAuthn ceremonies,
// OIDC and SAML flows. Signing in goes on, in a degraded mode, instead of
// failing on every request (audit B-11).
//
// What the degraded mode changes, while Valkey is unavailable:
//
//   - Each server counts and remembers on its own. With one server nothing
//     visible changes. With several, rate limits and counters apply per
//     server, and a flow started on one server is unknown to the others: it
//     fails there, unless the load balancer keeps a browser on one server
//     (and the code exchange of an application's backend reaches the same
//     server).
//   - What was written to Valkey before the outage cannot be read: the flows
//     in progress at that moment fail (closed), new ones work.
//   - A marker written to Valkey before the outage (a SAML request already
//     seen, a code already exchanged) is not seen: replay protection only
//     covers what this server saw itself during the outage.
//
// Only an unavailable Valkey (an error wrapping ErrUnavailable) switches to
// memory. Any other error (a command the server refused, a reply that makes
// no sense) is returned as before. Sessions do not need this package: their
// cache already falls back on PostgreSQL.
package fallback

import (
	"errors"
	"time"
)

// ErrUnavailable: the shared store does not answer (connection refused,
// lost or timed out), as opposed to a command it refused. The Valkey client
// of internal/cache/valkey wraps its network errors in it.
var ErrUnavailable = errors.New("valkey unavailable")

func unavailable(err error) bool { return errors.Is(err, ErrUnavailable) }

// errFull: the memory of the degraded mode is full, a new entry is refused.
// The caller fails as it would have without the fallback.
var errFull = errors.New("fallback: too many entries kept in memory while Valkey is unavailable")

// minTombstoneTTL: how long a key deleted from memory is remembered as
// deleted, at least. Longer than any key of the flow stores (10 minutes),
// so that an older value Valkey may still hold has expired by then.
const minTombstoneTTL = 15 * time.Minute

// sweepInterval: how often the expired entries are dropped.
const sweepInterval = time.Minute

// ttlMap holds entries until they expire, at most max of them. It is not
// safe for concurrent use: its owner holds a lock around each operation.
type ttlMap[V any] struct {
	now       func() time.Time
	max       int
	items     map[string]ttlEntry[V]
	nextSweep time.Time
}

type ttlEntry[V any] struct {
	v   V
	exp time.Time
}

func newTTLMap[V any](now func() time.Time, max int) *ttlMap[V] {
	if now == nil {
		now = time.Now
	}
	return &ttlMap[V]{now: now, max: max, items: map[string]ttlEntry[V]{}}
}

// get returns the entry of key unless it expired.
func (m *ttlMap[V]) get(key string) (V, bool) {
	e, ok := m.items[key]
	if ok && !m.now().Before(e.exp) {
		delete(m.items, key)
		ok = false
	}
	return e.v, ok
}

// set stores v under key for ttl. A new key is refused (errFull) when the
// map is full of entries that have not expired.
func (m *ttlMap[V]) set(key string, v V, ttl time.Duration) error {
	now := m.now()
	if !now.Before(m.nextSweep) {
		m.sweep(now)
	}
	if _, exists := m.items[key]; !exists && len(m.items) >= m.max {
		m.sweep(now)
		if len(m.items) >= m.max {
			return errFull
		}
	}
	m.items[key] = ttlEntry[V]{v: v, exp: now.Add(ttl)}
	return nil
}

func (m *ttlMap[V]) delete(key string) { delete(m.items, key) }

func (m *ttlMap[V]) sweep(now time.Time) {
	for k, e := range m.items {
		if !now.Before(e.exp) {
			delete(m.items, k)
		}
	}
	m.nextSweep = now.Add(sweepInterval)
}

// tombstones tracks the longest lifetime a store was asked for, so that a
// key deleted in memory stays deleted until any older copy Valkey holds has
// expired. Its owner holds the lock.
type tombstones struct{ longest time.Duration }

func (t *tombstones) saw(ttl time.Duration) {
	if ttl > t.longest {
		t.longest = ttl
	}
}

func (t *tombstones) ttl() time.Duration { return max(t.longest, minTombstoneTTL) }
