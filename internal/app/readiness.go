package app

import (
	"context"

	"sso.internal/sso/internal/health"
)

// ReadinessChecks are what a server needs to serve (GET /readyz). The KMS is
// not one of them: it is checked by a real signature, too slow to run for an
// orchestrator (the admin dashboard shows it). Without Valkey the servers
// serve in a degraded mode (internal/cache/fallback): /readyz then answers
// 200 {"status":"degraded"}, and its PING is also how an outage ends when no
// other request comes (the Docker healthcheck asks every few seconds).
func (c *Core) ReadinessChecks() []health.Check {
	return []health.Check{
		{Name: "PostgreSQL", Check: c.DB.PingContext},
		{Name: "Valkey", Degrades: true, Check: func(ctx context.Context) error {
			return c.Valkey.Do(ctx, c.Valkey.B().Ping().Build()).Error()
		}},
	}
}
