package valkey

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/lockoutstore"
)

type lockoutStore struct {
	client valkey.Client
}

// NewLockoutStore returns the Valkey implementation of lockoutstore.Store.
func NewLockoutStore(client valkey.Client) lockoutstore.Store {
	return &lockoutStore{client: client}
}

func lockoutKey(key string) string { return "lockout:" + key }

// casLockout compares and swaps in one step: Valkey runs a Lua script
// atomically, so no other command can slip between the GET and the SET.
// https://valkey.io/topics/eval-intro/
//
//	KEYS[1] the key, ARGV[1] expected value ("" = absent),
//	ARGV[2] new value ("" = delete), ARGV[3] TTL in milliseconds
var casLockout = valkey.NewLuaScript(`
local cur = redis.call('GET', KEYS[1])
if cur == false then cur = '' end
if cur ~= ARGV[1] then return 0 end
if ARGV[2] == '' then
  redis.call('DEL', KEYS[1])
else
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
end
return 1
`)

func (s *lockoutStore) Get(ctx context.Context, key string) (domain.LockoutState, error) {
	raw, err := s.client.Do(ctx, s.client.B().Get().Key(lockoutKey(key)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return domain.LockoutState{}, nil
	}
	if err != nil {
		return domain.LockoutState{}, fmt.Errorf("lockoutstore: get: %w", err)
	}
	st, err := lockoutstore.Decode(raw)
	if err != nil {
		return domain.LockoutState{}, fmt.Errorf("lockoutstore: decode: %w", err)
	}
	return st, nil
}

func (s *lockoutStore) CompareAndSwap(ctx context.Context, key string, old, next domain.LockoutState, ttl time.Duration) (bool, error) {
	if ttl < minTTL {
		ttl = minTTL
	}
	n, err := casLockout.Exec(ctx, s.client,
		[]string{lockoutKey(key)},
		[]string{lockoutstore.Encode(old), lockoutstore.Encode(next), strconv.FormatInt(ttl.Milliseconds(), 10)},
	).AsInt64()
	if err != nil {
		return false, fmt.Errorf("lockoutstore: compare and swap: %w", err)
	}
	return n == 1, nil
}
