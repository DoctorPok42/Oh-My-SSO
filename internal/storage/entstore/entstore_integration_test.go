package entstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

var testDSN string

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("sso_test"),
		postgres.WithUsername("sso"),
		postgres.WithPassword("sso"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start postgres container: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = pgContainer.Terminate(ctx) }()

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get connection string: %v\n", err)
		os.Exit(1)
	}
	testDSN = dsn

	setupClient, err := newEntClient(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed opening connection to postgres: %v\n", err)
		os.Exit(1)
	}
	if err := setupClient.Schema.Create(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed creating schema resources: %v\n", err)
		os.Exit(1)
	}
	_ = setupClient.Close()

	os.Exit(m.Run())
}

func newEntClient(dsn string) (*ent.Client, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	drv := entsql.OpenDB(dialect.Postgres, db)
	return ent.NewClient(ent.Driver(drv)), nil
}

func newTestClient(t *testing.T) *ent.Client {
	t.Helper()
	client, err := newEntClient(testDSN)
	if err != nil {
		t.Fatalf("failed opening ent client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newTestRealm(t *testing.T, ctx context.Context, client *ent.Client) *domain.Realm {
	t.Helper()
	realmRepo := entstore.NewRealmRepository(client)
	r, err := realmRepo.Create(ctx, repository.CreateRealmParams{
		Name: "test-realm-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("failed to create test realm: %v", err)
	}
	return r
}
