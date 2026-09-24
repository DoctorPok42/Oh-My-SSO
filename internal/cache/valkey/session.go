package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/sessioncache"
)

const minTTL = time.Second

type sessionCache struct {
	client valkey.Client
}

func NewSessionCache(client valkey.Client) sessioncache.Cache {
	return &sessionCache{client: client}
}

func sessionKey(tokenHash string) string   { return "session:{" + tokenHash + "}" }
func tombstoneKey(tokenHash string) string { return "session:{" + tokenHash + "}:revoked" }

func (c *sessionCache) Get(ctx context.Context, tokenHash string) (sessioncache.Result, error) {
	msgs, err := c.client.Do(ctx, c.client.B().Mget().
		Key(sessionKey(tokenHash), tombstoneKey(tokenHash)).
		Build()).ToArray()
	if err != nil {
		return sessioncache.Result{}, fmt.Errorf("sessioncache: mget: %w", err)
	}
	if len(msgs) != 2 {
		return sessioncache.Result{}, fmt.Errorf("sessioncache: mget: unexpected %d replies", len(msgs))
	}

	var res sessioncache.Result
	if !msgs[1].IsNil() {
		res.Revoked = true
		return res, nil
	}
	if msgs[0].IsNil() {
		return res, nil
	}

	raw, err := msgs[0].ToString()
	if err != nil {
		return sessioncache.Result{}, fmt.Errorf("sessioncache: read entry: %w", err)
	}
	var e sessioncache.Entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return sessioncache.Result{}, fmt.Errorf("sessioncache: unmarshal entry: %w", err)
	}
	res.Entry = &e
	return res, nil
}

func (c *sessionCache) Fill(ctx context.Context, tokenHash string, e sessioncache.Entry, ttl time.Duration) error {
	if ttl < minTTL {
		return nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	err = c.client.Do(ctx, c.client.B().Set().
		Key(sessionKey(tokenHash)).Value(string(data)).
		Nx().Ex(ttl).
		Build()).Error()
	if err != nil && !valkey.IsValkeyNil(err) {
		return fmt.Errorf("sessioncache: fill: %w", err)
	}
	return nil
}

func (c *sessionCache) Refresh(ctx context.Context, tokenHash string, e sessioncache.Entry, ttl time.Duration) error {
	if ttl < minTTL {
		return nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	err = c.client.Do(ctx, c.client.B().Set().
		Key(sessionKey(tokenHash)).Value(string(data)).
		Xx().Ex(ttl).
		Build()).Error()

	if err != nil && !valkey.IsValkeyNil(err) {
		return fmt.Errorf("sessioncache: refresh: %w", err)
	}
	return nil
}

func (c *sessionCache) MarkRevoked(ctx context.Context, tokenHash string, ttl time.Duration) error {
	if ttl < minTTL {
		ttl = minTTL
	}

	if err := c.client.Do(ctx, c.client.B().Set().
		Key(tombstoneKey(tokenHash)).Value("1").
		Ex(ttl).
		Build()).Error(); err != nil {
		return fmt.Errorf("sessioncache: tombstone: %w", err)
	}
	if err := c.client.Do(ctx, c.client.B().Del().
		Key(sessionKey(tokenHash)).
		Build()).Error(); err != nil {
		return fmt.Errorf("sessioncache: del: %w", err)
	}
	return nil
}
