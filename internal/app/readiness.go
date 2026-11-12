package app

import (
	"context"

	"sso.internal/sso/internal/health"
)

// ReadinessChecks are what a server needs to serve (GET /readyz). The KMS is
// not one of them: it is checked by a real signature, too slow to run for an
// orchestrator (the admin dashboard shows it).
func (c *Core) ReadinessChecks() []health.Check {
	return []health.Check{
		{Name: "PostgreSQL", Check: c.DB.PingContext},
		{Name: "Valkey", Check: func(ctx context.Context) error {
			return c.Valkey.Do(ctx, c.Valkey.B().Ping().Build()).Error()
		}},
	}
}
