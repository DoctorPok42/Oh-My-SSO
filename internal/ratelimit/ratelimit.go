package ratelimit

import (
	"context"
	"time"
)

type Limiter interface {
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error)
}

func Key(route, realmID, scope, value string) string {
	return route + ":" + realmID + ":" + scope + ":" + value
}
