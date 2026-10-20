package httpserver_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Containers of the integration tests of this package.
//
// One PostgreSQL and one Valkey for the whole `go test` run, started on
// first use, instead of a new pair for every test. Each test still gets an
// empty database of its own (CREATE DATABASE), so tests stay independent.
// Valkey is shared as is: every key the server writes is scoped by a realm,
// client, user or random token id, all unique per test.
//
// Why: starting ~15 container pairs made the suite slow (~100 s) and
// exposed it to Docker hiccups. The PostgreSQL readiness check also no
// longer reads the container logs ("database system is ready…" twice):
// with Docker Desktop on Windows/WSL the log stream can miss those lines
// and the test then hangs until its timeout although the database is up.
// It now asks PostgreSQL itself (pg_isready over TCP, inside the
// container), then checks that the mapped port answers from the host.

const (
	pgUser     = "sso"
	pgPassword = "sso"
	pgAdminDB  = "sso_test"
)

var (
	pgOnce      sync.Once
	pgContainer *postgres.PostgresContainer
	pgAdminDSN  string
	pgErr       error

	valkeyOnce      sync.Once
	valkeyContainer testcontainers.Container
	valkeyAddr      string
	valkeyErr       error
)

// TestMain stops the shared containers at the end of the run (Ryuk would
// remove them anyway, unless TESTCONTAINERS_RYUK_DISABLED is set).
func TestMain(m *testing.M) {
	code := m.Run()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if pgContainer != nil {
		_ = pgContainer.Terminate(ctx)
	}
	if valkeyContainer != nil {
		_ = valkeyContainer.Terminate(ctx)
	}
	os.Exit(code)
}

// startTestPostgres returns the DSN of a new, empty database for this test.
func startTestPostgres(t *testing.T, ctx context.Context) string {
	t.Helper()
	pgOnce.Do(func() { pgErr = runPostgres(ctx) })
	require.NoError(t, pgErr, "shared PostgreSQL container")

	admin, err := sql.Open("pgx", pgAdminDSN)
	require.NoError(t, err)
	defer admin.Close()

	name := "t_" + strings.ToLower(rand.Text())
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		// Runs after the test's own cleanups (they were registered later):
		// its connections are closed by then; FORCE handles stragglers.
		a, err := sql.Open("pgx", pgAdminDSN)
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return strings.Replace(pgAdminDSN, "/"+pgAdminDB+"?", "/"+name+"?", 1)
}

// startTestValkey returns the address of the shared Valkey.
func startTestValkey(t *testing.T, ctx context.Context) string {
	t.Helper()
	valkeyOnce.Do(func() { valkeyErr = runValkey(ctx) })
	require.NoError(t, valkeyErr, "shared Valkey container")
	return valkeyAddr
}

// runPostgres starts the container, with one retry: a failed start (Docker
// busy) should not fail the whole suite.
func runPostgres(ctx context.Context) error {
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		var c *postgres.PostgresContainer
		c, err = postgres.Run(ctx, "postgres:16",
			postgres.WithDatabase(pgAdminDB),
			postgres.WithUsername(pgUser),
			postgres.WithPassword(pgPassword),
			// Ready = pg_isready succeeds over TCP. The temporary server of
			// the image's init phase only listens on a unix socket, so this
			// cannot succeed too early. Then the port must answer from the
			// host (Docker Desktop starts a port proxy of its own).
			testcontainers.WithWaitStrategy(
				wait.ForExec([]string{"pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", pgUser, "-d", pgAdminDB}).
					WithStartupTimeout(2*time.Minute).WithPollInterval(250*time.Millisecond),
				wait.ForListeningPort("5432/tcp").WithStartupTimeout(time.Minute),
			),
		)
		if err == nil {
			pgContainer = c
			pgAdminDSN, err = c.ConnectionString(ctx, "sslmode=disable")
			return err
		}
		log.Printf("integration tests: PostgreSQL did not start (attempt %d): %v", attempt, err)
		if c != nil {
			_ = c.Terminate(context.Background())
		}
	}
	return err
}

func runValkey(ctx context.Context) error {
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		var c testcontainers.Container
		c, err = testcontainers.Run(ctx, "valkey/valkey:latest",
			testcontainers.WithExposedPorts("6379/tcp"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp").WithStartupTimeout(time.Minute)),
		)
		if err == nil {
			valkeyContainer = c
			host, err := c.Host(ctx)
			if err != nil {
				return err
			}
			port, err := c.MappedPort(ctx, "6379/tcp")
			if err != nil {
				return err
			}
			valkeyAddr = host + ":" + port.Port()
			return nil
		}
		log.Printf("integration tests: Valkey did not start (attempt %d): %v", attempt, err)
		if c != nil {
			_ = c.Terminate(context.Background())
		}
	}
	return err
}
