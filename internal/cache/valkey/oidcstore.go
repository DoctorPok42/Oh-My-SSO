package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/oidcstore"
)

type oidcStore struct {
	client valkey.Client
}

// NewOIDCStore returns the Valkey implementation of oidcstore.Store.
func NewOIDCStore(client valkey.Client) oidcstore.Store {
	return &oidcStore{client: client}
}

func (s *oidcStore) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl < minTTL {
		ttl = minTTL
	}
	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(valkey.BinaryString(value)).Ex(ttl).Build()).Error(); err != nil {
		return fmt.Errorf("oidcstore: put: %w", err)
	}
	return nil
}

func (s *oidcStore) PutIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if ttl < minTTL {
		ttl = minTTL
	}
	// SET ... NX answers OK when it wrote the key, nil when it already existed.
	err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(valkey.BinaryString(value)).Nx().Ex(ttl).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("oidcstore: put if absent: %w", err)
	}
	return true, nil
}

func (s *oidcStore) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidcstore: get: %w", err)
	}
	return b, nil
}

func (s *oidcStore) Take(ctx context.Context, key string) ([]byte, error) {
	// GETDEL (Valkey / Redis >= 6.2): read and delete in one atomic command.
	b, err := s.client.Do(ctx, s.client.B().Getdel().Key(key).Build()).AsBytes()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidcstore: take: %w", err)
	}
	return b, nil
}

func (s *oidcStore) Delete(ctx context.Context, key string) error {
	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("oidcstore: delete: %w", err)
	}
	return nil
}
