package valkey_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/cache/fallback"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/cache/valkey/valkeytest"
	"sso.internal/sso/internal/ratelimit"
)

const testPassword = "integration-secret"

var (
	valkeyOnce sync.Once
	valkeyAddr string
	valkeyErr  error
)

// startValkey: one Valkey with a password for the package (requirepass,
// as compose.example.yml).
func startValkey(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	valkeyOnce.Do(func() {
		ctx := context.Background()
		c, err := testcontainers.Run(ctx, "valkey/valkey:latest",
			testcontainers.WithExposedPorts("6379/tcp"),
			testcontainers.WithCmd("valkey-server", "--requirepass", testPassword),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp").WithStartupTimeout(time.Minute)),
		)
		if err != nil {
			valkeyErr = err
			return
		}
		host, err := c.Host(ctx)
		if err != nil {
			valkeyErr = err
			return
		}
		port, err := c.MappedPort(ctx, "6379/tcp")
		if err != nil {
			valkeyErr = err
			return
		}
		valkeyAddr = host + ":" + port.Port()
	})
	require.NoError(t, valkeyErr, "Valkey container")
	return valkeyAddr
}

func open(t *testing.T, o valkeycache.Options) (valkey.Client, error) {
	t.Helper()
	c, err := valkeycache.Open(o)
	if err != nil {
		return nil, err
	}
	if err := c.Do(context.Background(), c.B().Ping().Build()).Error(); err != nil {
		c.Close()
		return nil, err
	}
	t.Cleanup(c.Close)
	return c, nil
}

func TestOpenCredentials_Integration(t *testing.T) {
	addr := startValkey(t)
	ctx := context.Background()

	_, err := open(t, valkeycache.Options{Addresses: []string{addr}})
	require.Error(t, err, "no password: refused")
	_, err = open(t, valkeycache.Options{Addresses: []string{addr}, Password: "wrong"})
	require.Error(t, err, "wrong password: refused")

	admin, err := open(t, valkeycache.Options{Addresses: []string{addr}, Password: testPassword})
	require.NoError(t, err)

	// An ACL user of its own, as on a shared or managed Valkey.
	require.NoError(t, admin.Do(ctx, admin.B().Arbitrary("ACL", "SETUSER").Args("sso", "on", ">user-secret", "~*", "&*", "+@all").Build()).Error())
	user, err := open(t, valkeycache.Options{Addresses: []string{addr}, Username: "sso", Password: "user-secret"})
	require.NoError(t, err)
	_, err = open(t, valkeycache.Options{Addresses: []string{addr}, Username: "sso", Password: testPassword})
	require.Error(t, err, "the user's own password, not requirepass")

	// A logical database apart from the others.
	db2, err := open(t, valkeycache.Options{Addresses: []string{addr}, Password: testPassword, DB: 2})
	require.NoError(t, err)
	require.NoError(t, db2.Do(ctx, db2.B().Set().Key("db-test").Value("in 2").Build()).Error())
	err = user.Do(ctx, user.B().Get().Key("db-test").Build()).Error()
	require.True(t, valkey.IsValkeyNil(err), "db 0 does not see db 2: %v", err)
}

// TestDegradedMode_Integration: Valkey cut off for real (connections closed,
// new ones refused), then back.
func TestDegradedMode_Integration(t *testing.T) {
	addr := startValkey(t)
	ctx := context.Background()
	proxy := valkeytest.NewProxy(t, addr)
	raw, err := open(t, valkeycache.Options{Addresses: []string{proxy.Addr()}, Password: testPassword})
	require.NoError(t, err)
	client, guard := valkeycache.Guarded(raw)

	limiter := fallback.NewLimiter(valkeycache.NewRateLimiter(client), nil)
	flows := fallback.NewFlowStore(valkeycache.NewOIDCStore(client), nil)
	rule := ratelimit.Rule{Key: "it:" + t.Name(), Limit: 100, Window: time.Minute}
	local := ratelimit.NewMemory(nil) // only to tell memory's hits apart (Owns)

	res, err := limiter.Reserve(ctx, rule)
	require.NoError(t, err)
	require.True(t, res.OK)
	require.False(t, local.Owns(res.Hits[0]), "counted in Valkey")
	require.NoError(t, flows.Put(ctx, "it:before", []byte("in valkey"), time.Minute))

	proxy.Down()
	start := time.Now()
	res, err = limiter.Reserve(ctx, rule)
	require.NoError(t, err, "the rate limit goes on in memory")
	require.True(t, res.OK)
	require.True(t, local.Owns(res.Hits[0]))
	require.Less(t, time.Since(start), 5*time.Second)
	require.ErrorIs(t, guard.Err(), fallback.ErrUnavailable)

	// Then the commands fail at once: no request waits for the network.
	start = time.Now()
	for range 50 {
		res, err := limiter.Reserve(ctx, rule)
		require.NoError(t, err)
		require.True(t, res.OK)
	}
	require.Less(t, time.Since(start), time.Second, "50 reservations during the outage")

	require.NoError(t, flows.Put(ctx, "it:during", []byte("in memory"), time.Minute))
	v, err := flows.Get(ctx, "it:during")
	require.NoError(t, err)
	require.Equal(t, "in memory", string(v))
	_, err = flows.Get(ctx, "it:before")
	require.ErrorIs(t, err, fallback.ErrUnavailable, "what Valkey holds cannot be read: closed")

	// Back: the next probe (every 2 s) ends the outage.
	proxy.Up(t)
	require.Eventually(t, func() bool {
		_, err := flows.Get(ctx, "it:before")
		return err == nil
	}, 15*time.Second, 100*time.Millisecond)
	require.NoError(t, guard.Err())
	v, err = flows.Get(ctx, "it:before")
	require.NoError(t, err)
	require.Equal(t, "in valkey", string(v))
	v, err = flows.Get(ctx, "it:during")
	require.NoError(t, err)
	require.Equal(t, "in memory", string(v), "a flow started during the outage goes on")
	res, err = limiter.Reserve(ctx, rule)
	require.NoError(t, err)
	require.False(t, local.Owns(res.Hits[0]), "counted in Valkey again")

	// The Valkey client's own errors are not an outage.
	err = client.Do(ctx, client.B().Arbitrary("NOSUCHCOMMAND").Build()).Error()
	require.Error(t, err)
	require.False(t, errors.Is(err, fallback.ErrUnavailable))
	require.NoError(t, guard.Err())
}
