package entstore

import (
	"context"
	stdsql "database/sql"
	"errors"
	"fmt"
	"sync/atomic"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"sso.internal/sso/internal/core/repository"
)

// Driver is the ent driver of the stores, and their Transactor. A query
// whose context carries a transaction of InTx runs in it: every repository
// built on a client of this driver joins the transaction without knowing
// it. The transactions ent opens itself (a write that changes edges, an
// UpdateOne, withTx) join it too: their Commit and Rollback do nothing and
// InTx ends the transaction, the way ent's own transactional client treats
// its builders.
//
// It only has the methods of dialect.Driver (and BeginTx, which
// ent.Client.BeginTx asks for): the *sql.DB methods that entsql.Driver
// also has would bypass the transaction.
type Driver struct {
	drv *entsql.Driver
}

var (
	_ dialect.Driver        = (*Driver)(nil)
	_ repository.Transactor = (*Driver)(nil)
)

// NewDriver is the driver of the PostgreSQL pool db:
//
//	drv := entstore.NewDriver(db)
//	client := ent.NewClient(ent.Driver(drv)) // repositories: entstore.NewXxxRepository(client)
//	tx := drv                                // their repository.Transactor
func NewDriver(db *stdsql.DB) *Driver {
	return &Driver{drv: entsql.OpenDB(dialect.Postgres, db)}
}

type txKey struct{}

// ambientTx is the transaction a context carries, and the driver that
// opened it: a context never makes the client of another database use it.
type ambientTx struct {
	owner *Driver
	tx    dialect.Tx
	ended atomic.Bool // committed or rolled back
}

// current is the open transaction of ctx, if any. A context kept after its
// InTx (a goroutine started inside) carries an ended transaction: its
// queries run on their own, and an InTx with it opens a new transaction.
func (d *Driver) current(ctx context.Context) dialect.Tx {
	if a, ok := ctx.Value(txKey{}).(*ambientTx); ok && a.owner == d && !a.ended.Load() {
		return a.tx
	}
	return nil
}

// InTx implements repository.Transactor.
func (d *Driver) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if d.current(ctx) != nil {
		return fn(ctx) // already in one: the outer InTx ends it
	}
	tx, err := d.drv.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	a := &ambientTx{owner: d, tx: tx}
	committing := false
	// Whatever ends fn (an error, a panic, runtime.Goexit), the
	// transaction does not stay open and its connection goes back to the
	// pool. A panic goes on after the rollback.
	defer func() {
		a.ended.Store(true)
		if !committing {
			_ = tx.Rollback() // a broken connection rolls back by itself
		}
	}()
	if err := fn(context.WithValue(ctx, txKey{}, a)); err != nil {
		return err
	}
	committing = true // a failed commit ends the transaction too
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (d *Driver) Exec(ctx context.Context, query string, args, v any) error {
	if tx := d.current(ctx); tx != nil {
		return tx.Exec(ctx, query, args, v)
	}
	return d.drv.Exec(ctx, query, args, v)
}

func (d *Driver) Query(ctx context.Context, query string, args, v any) error {
	if tx := d.current(ctx); tx != nil {
		return tx.Query(ctx, query, args, v)
	}
	return d.drv.Query(ctx, query, args, v)
}

func (d *Driver) Tx(ctx context.Context) (dialect.Tx, error) {
	return d.BeginTx(ctx, nil)
}

// errTxOptions: the transaction of InTx is already open, with its options.
var errTxOptions = errors.New("entstore: cannot change the options of the transaction in progress")

func (d *Driver) BeginTx(ctx context.Context, opts *stdsql.TxOptions) (dialect.Tx, error) {
	if tx := d.current(ctx); tx != nil {
		if opts != nil && *opts != (stdsql.TxOptions{}) {
			return nil, errTxOptions
		}
		return joinedTx{tx}, nil
	}
	return d.drv.BeginTx(ctx, opts)
}

func (d *Driver) Close() error    { return d.drv.Close() }
func (d *Driver) Dialect() string { return d.drv.Dialect() }

// joinedTx is a transaction opened inside InTx: it runs in the transaction
// of InTx, which alone commits or rolls back. A failure inside is returned
// to fn, which ends with it: the whole transaction is rolled back.
type joinedTx struct{ dialect.Tx }

func (joinedTx) Commit() error   { return nil }
func (joinedTx) Rollback() error { return nil }
