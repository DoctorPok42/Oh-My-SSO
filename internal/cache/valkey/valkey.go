package valkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/httpcache"
	"sso.internal/sso/internal/ratelimit"
)

func New(addr string) (valkey.Client, error) {
	return valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
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
