package fallback

import (
	"context"
	"errors"
	"time"

	"sso.internal/sso/internal/ratelimit"
)

// Limiter is the rate limiter of the servers: Valkey, shared by every
// server, and a limiter of this server's memory while Valkey is unavailable.
// Limits then apply per server, and the hits counted in memory are not
// carried over when Valkey comes back (a client gets a fresh window at
// worst). Without it, every sign-in, token request and SAML message would be
// refused with a 500 while Valkey is down.
type Limiter struct {
	primary ratelimit.Limiter
	local   *ratelimit.Memory
}

var _ ratelimit.Limiter = (*Limiter)(nil)

// NewLimiter wraps primary (Valkey). now may be nil (time.Now).
func NewLimiter(primary ratelimit.Limiter, now func() time.Time) *Limiter {
	return &Limiter{primary: primary, local: ratelimit.NewMemory(now)}
}

func (l *Limiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	res, err := l.Reserve(ctx, ratelimit.Rule{Key: key, Limit: limit, Window: window})
	return res.OK, err
}

func (l *Limiter) Reserve(ctx context.Context, rules ...ratelimit.Rule) (ratelimit.Reservation, error) {
	res, err := l.primary.Reserve(ctx, rules...)
	if unavailable(err) {
		return l.local.Reserve(ctx, rules...)
	}
	return res, err
}

// Release gives each hit back to the limiter that counted it.
func (l *Limiter) Release(ctx context.Context, hits ...ratelimit.Hit) error {
	var shared []ratelimit.Hit
	var local []ratelimit.Hit
	for _, h := range hits {
		if l.local.Owns(h) {
			local = append(local, h)
		} else {
			shared = append(shared, h)
		}
	}
	return errors.Join(l.local.Release(ctx, local...), l.primary.Release(ctx, shared...))
}
