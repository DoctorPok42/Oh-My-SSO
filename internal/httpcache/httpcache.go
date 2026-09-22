package httpcache

import (
	"context"
	"time"
)

type Cache interface {
	Get(ctx context.Context, route, realmID, userID string) (data []byte, ok bool, err error)
	Set(ctx context.Context, route, realmID, userID string, data []byte, ttl time.Duration) error
	InvalidateUser(ctx context.Context, route, realmID, userID string) error
	InvalidateAll(ctx context.Context, route, realmID string) error
}
