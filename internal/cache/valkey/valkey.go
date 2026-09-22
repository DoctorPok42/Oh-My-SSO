package valkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/httpcache"
	"sso.internal/sso/internal/ratelimit"
)

func New(addr string) (valkey.Client, error) {
	return valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
}

type rateLimiter struct {
	client valkey.Client
}

func NewRateLimiter(client valkey.Client) ratelimit.Limiter {
	return &rateLimiter{client: client}
}

func (l *rateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	now := time.Now()
	cutoff := now.Add(-window).UnixMilli()

	if err := l.client.Do(ctx, l.client.B().Zremrangebyscore().
		Key(key).Min("-inf").Max(strconv.FormatInt(cutoff, 10)).
		Build()).Error(); err != nil {
		return false, fmt.Errorf("ratelimit: zremrangebyscore %q: %w", key, err)
	}

	count, err := l.client.Do(ctx, l.client.B().Zcard().Key(key).Build()).ToInt64()
	if err != nil {
		return false, fmt.Errorf("ratelimit: zcard %q: %w", key, err)
	}
	if count >= limit {
		return false, nil
	}

	member, err := uniqueMember(now)
	if err != nil {
		return false, fmt.Errorf("ratelimit: generate member: %w", err)
	}
	if err := l.client.Do(ctx, l.client.B().Zadd().
		Key(key).ScoreMember().ScoreMember(float64(now.UnixMilli()), member).
		Build()).Error(); err != nil {
		return false, fmt.Errorf("ratelimit: zadd %q: %w", key, err)
	}

	if err := l.client.Do(ctx, l.client.B().Expire().
		Key(key).Seconds(int64(window.Seconds())+1).
		Build()).Error(); err != nil {
		return false, fmt.Errorf("ratelimit: expire %q: %w", key, err)
	}

	return true, nil
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
