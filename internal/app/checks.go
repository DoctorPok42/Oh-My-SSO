package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/health"
	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/logging"
	"sso.internal/sso/internal/metrics"
)

// DependencyChecks are the dependencies of both servers, as the admin
// dashboard shows them ("Infrastructure"). /metrics runs the same checks
// (omsso_dependency_up), idp doctor goes further.
func (c *Core) DependencyChecks() []health.Check {
	return []health.Check{
		{Name: "PostgreSQL", Check: c.queryDatabase},
		{Name: "Valkey", Check: c.pingValkey},
		{Name: "Key manager (" + c.KMSBackend + ")", Check: c.signWithKMS},
		{Name: "Notifications (SMTP)", Check: dialSMTP},
	}
}

// ServeMetrics serves /metrics on METRICS_ADDR (e.g. :9100), a listener of
// its own: never the public port. Empty: no metrics.
func (c *Core) ServeMetrics() {
	addr := os.Getenv("METRICS_ADDR")
	if addr == "" {
		return
	}
	err := metrics.Serve(addr, map[string]func(context.Context) error{
		"postgresql": c.queryDatabase, "valkey": c.pingValkey, "kms": c.signWithKMS, "smtp": dialSMTP,
	})
	if err != nil {
		logging.Fatal("metrics: cannot listen", "addr", addr, "error", err)
	}
	slog.Info("metrics listening", "addr", addr)
}

func (c *Core) queryDatabase(ctx context.Context) error {
	_, err := c.Ent.Realm.Query().Exist(ctx)
	return err
}

func (c *Core) pingValkey(ctx context.Context) error {
	return c.Valkey.Do(ctx, c.Valkey.B().Ping().Build()).Error()
}

func (c *Core) signWithKMS(ctx context.Context) error {
	return SignWithKMS(ctx, c.KeyManager, c.Realms, c.SigningKeys)
}

// SignWithKMS signs with the master realm's JWT key: proves the KMS answers
// and holds the key.
func SignWithKMS(ctx context.Context, km keymanager.KeyManager, realms repository.RealmRepository,
	keys repository.SigningKeyRepository) error {
	master, err := realms.GetByName(ctx, "master")
	if err != nil {
		return fmt.Errorf("master realm (idp-admin bootstrap creates it): %w", err)
	}
	list, err := keys.ListByRealm(ctx, master.ID)
	if err != nil {
		return err
	}
	for _, k := range list {
		if k.Status == domain.SigningKeyActive && k.Purpose == domain.SigningKeyPurposeJWT {
			_, err := km.Sign(ctx, k.KMSKeyReference, []byte("omsso-health"))
			return err
		}
	}
	return errors.New("the master realm has no active signing key")
}

// dialSMTP: the mail server accepts a connection. No AUTH: it runs at each
// scrape, and a provider may limit the sign-ins.
func dialSMTP(ctx context.Context) error {
	addr := SMTPAddress()
	if addr == "" {
		return health.ErrDisabled
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}
