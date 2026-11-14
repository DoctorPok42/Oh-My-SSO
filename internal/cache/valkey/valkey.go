package valkey

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/cache/fallback"
	"sso.internal/sso/internal/httpcache"
	"sso.internal/sso/internal/ratelimit"
)

// Options tell how to reach Valkey (app.ValkeyOptions reads them from the
// environment).
type Options struct {
	// Addresses: host:port of the server, of nodes of a cluster (any of
	// them: the client finds the others), or of the sentinels when
	// SentinelMaster is set.
	Addresses []string
	// Username: an ACL user; empty is "default", the user of requirepass.
	Username string
	Password string
	// TLS, when not nil: every connection is TLS, to the sentinels too. The
	// server's certificate must match the host name of its address.
	TLS *tls.Config
	// SentinelMaster: the name of the master the sentinels watch. The
	// client asks them where the master is, and follows a failover.
	SentinelMaster string
	// SentinelPassword: the sentinels' own password, when they have one.
	SentinelPassword string
	// DB: the logical database (SELECT), to share a server with other
	// applications. A cluster only has 0.
	DB int
}

// Open connects to Valkey: it fails when no address answers or the server
// refuses the credentials.
func Open(o Options) (valkey.Client, error) {
	opt := valkey.ClientOption{
		InitAddress: o.Addresses,
		Username:    o.Username,
		Password:    o.Password,
		TLSConfig:   o.TLS,
		SelectDB:    o.DB,
		// Nothing here uses client-side caching (DoCache). Without this, every
		// connection sends CLIENT TRACKING, which a restricted ACL user of a
		// managed Valkey may not be allowed, and which RESP2 servers lack.
		DisableCache: true,
		// A few retries of a read cut by a network error (a reconnection),
		// then the error. valkey-go's default retries until the context ends,
		// and a request's context has no deadline: during an outage, every
		// read would hang until the browser gave up, and the degraded mode
		// (Guard) would never see the error.
		RetryDelay: retryDelay,
		// Unreachable host (packets dropped): give up a connection after this,
		// not the default 5 s.
		Dialer: net.Dialer{Timeout: dialTimeout},
	}
	if o.SentinelMaster != "" {
		opt.Sentinel = valkey.SentinelOption{
			MasterSet: o.SentinelMaster,
			Password:  o.SentinelPassword,
			TLSConfig: o.TLS,
			// A +switch-master event missed (network blip) would bind the
			// client to the former master until a restart: ask the sentinels
			// now and then as well.
			TopologyRefreshInterval: 5 * time.Second,
		}
	}
	return valkey.NewClient(opt)
}

const (
	// maxRetries: how many times a retryable command (a read) is sent again
	// after a network error, before the error is returned.
	maxRetries  = 2
	dialTimeout = 2 * time.Second
)

// retryDelay: 50 ms, then 100 ms, then no more retry (a negative delay).
func retryDelay(attempts int, _ valkey.Completed, _ error) time.Duration {
	if attempts > maxRetries {
		return -1
	}
	return time.Duration(attempts) * 50 * time.Millisecond
}

// New connects to one server without credentials (tests, development).
func New(addr string) (valkey.Client, error) {
	return Open(Options{Addresses: []string{addr}})
}

// rateLimiter: one sorted set of hit times per key.
type rateLimiter struct {
	client valkey.Client
}

func NewRateLimiter(client valkey.Client) ratelimit.Limiter {
	return &rateLimiter{client: client}
}

func (l *rateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	res, err := l.Reserve(ctx, ratelimit.Rule{Key: key, Limit: limit, Window: window})
	return res.OK, err
}

// reserveScript checks and counts one key in one atomic step (KEYS[1];
// ARGV: now and window in ms, limit, member). It drops the hits older than
// the window, then adds one if there is room: {1, 0}. Otherwise {0, retry}:
// the ms until the hit that keeps the count at the limit (the
// (n-limit+1)th oldest) leaves the window.
var reserveScript = valkey.NewLuaScript(`
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count < limit then
  redis.call('ZADD', KEYS[1], now, ARGV[4])
  redis.call('PEXPIRE', KEYS[1], window + 1000)
  return {1, 0}
end
local retry = window
if limit > 0 then
  local hit = redis.call('ZRANGE', KEYS[1], count - limit, count - limit, 'WITHSCORES')
  if hit[2] then
    retry = tonumber(hit[2]) + window - now
  end
end
if retry < 0 then
  retry = 0
end
return {0, retry}
`)

// Reserve runs the script for every rule in one round trip, then removes
// the hits counted when another rule refused or failed.
func (l *rateLimiter) Reserve(ctx context.Context, rules ...ratelimit.Rule) (ratelimit.Reservation, error) {
	if len(rules) == 0 {
		return ratelimit.Reservation{OK: true}, nil
	}
	now := time.Now()
	nowMS := strconv.FormatInt(now.UnixMilli(), 10)
	hits := make([]ratelimit.Hit, len(rules))
	execs := make([]valkey.LuaExec, len(rules))
	for i, r := range rules {
		member, err := uniqueMember(now)
		if err != nil {
			return ratelimit.Reservation{}, fmt.Errorf("ratelimit: generate member: %w", err)
		}
		hits[i] = ratelimit.Hit{Key: r.Key, Member: member}
		execs[i] = valkey.LuaExec{Keys: []string{r.Key}, Args: []string{
			nowMS, strconv.FormatInt(r.Window.Milliseconds(), 10), strconv.FormatInt(r.Limit, 10), member}}
	}

	res := ratelimit.Reservation{OK: true}
	var failed error
	for i, resp := range reserveScript.ExecMulti(ctx, l.client, execs...) {
		out, err := resp.AsIntSlice()
		if err == nil && len(out) != 2 {
			err = fmt.Errorf("unexpected reply %v", out)
		}
		if err != nil {
			failed = fmt.Errorf("ratelimit: reserve %q: %w", rules[i].Key, err)
			continue
		}
		if out[0] != 1 {
			res.OK = false
			res.RetryAfter = max(res.RetryAfter, time.Duration(out[1])*time.Millisecond)
		}
	}
	if failed == nil && res.OK {
		res.Hits = hits
		return res, nil
	}

	// All or none. Removing a member that was not added is harmless, so
	// every hit is released: on an error, which ones counted is unknown.
	// Not when Valkey is unreachable: the release would fail as well (a
	// warning per request during an outage), and the hits leave the window.
	if errors.Is(failed, fallback.ErrUnavailable) {
		return ratelimit.Reservation{}, failed
	}
	if err := l.Release(context.WithoutCancel(ctx), hits...); err != nil {
		slog.WarnContext(ctx, "ratelimit: give back the hits of a refused reservation", "error", err)
	}
	if failed != nil {
		return ratelimit.Reservation{}, failed
	}
	return ratelimit.Reservation{RetryAfter: res.RetryAfter}, nil
}

func (l *rateLimiter) Release(ctx context.Context, hits ...ratelimit.Hit) error {
	if len(hits) == 0 {
		return nil
	}
	cmds := make([]valkey.Completed, len(hits))
	for i, h := range hits {
		cmds[i] = l.client.B().Zrem().Key(h.Key).Member(h.Member).Build()
	}
	for i, resp := range l.client.DoMulti(ctx, cmds...) {
		if err := resp.Error(); err != nil {
			return fmt.Errorf("ratelimit: zrem %q: %w", hits[i].Key, err)
		}
	}
	return nil
}

func uniqueMember(t time.Time) (string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", t.UnixMilli(), hex.EncodeToString(nonce)), nil
}

func generationKey(route, realmID string) string {
	return "cachegen:" + route + ":" + realmID
}

type httpCache struct {
	client valkey.Client
}

func NewHTTPCache(client valkey.Client) httpcache.Cache {
	return &httpCache{client: client}
}

func (c *httpCache) currentGeneration(ctx context.Context, route, realmID string) (int64, error) {
	gen, err := c.client.Do(ctx, c.client.B().Get().Key(generationKey(route, realmID)).Build()).ToInt64()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return 0, nil
		}
		return 0, err
	}
	return gen, nil
}

func (c *httpCache) entryKey(ctx context.Context, route, realmID, userID string) (string, error) {
	gen, err := c.currentGeneration(ctx, route, realmID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("cache:%s:%s:v%d:user:%s", route, realmID, gen, userID), nil
}

func (c *httpCache) Get(ctx context.Context, route, realmID, userID string) ([]byte, bool, error) {
	key, err := c.entryKey(ctx, route, realmID, userID)
	if err != nil {
		return nil, false, err
	}
	data, err := c.client.Do(ctx, c.client.B().Get().Key(key).Build()).AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func (c *httpCache) Set(ctx context.Context, route, realmID, userID string, data []byte, ttl time.Duration) error {
	key, err := c.entryKey(ctx, route, realmID, userID)
	if err != nil {
		return err
	}
	return c.client.Do(ctx, c.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build()).Error()
}

func (c *httpCache) InvalidateUser(ctx context.Context, route, realmID, userID string) error {
	key, err := c.entryKey(ctx, route, realmID, userID)
	if err != nil {
		return err
	}
	return c.client.Do(ctx, c.client.B().Del().Key(key).Build()).Error()
}

func (c *httpCache) InvalidateAll(ctx context.Context, route, realmID string) error {
	return c.client.Do(ctx, c.client.B().Incr().Key(generationKey(route, realmID)).Build()).Error()
}
