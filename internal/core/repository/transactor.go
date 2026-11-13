package repository

import "context"

// Transactor runs several repository calls as one database transaction:
// they are all written, or none is.
type Transactor interface {
	// InTx runs fn in a transaction, committed when fn returns nil and
	// rolled back when it returns an error (returned as is) or panics.
	// Every repository call made with the context fn receives joins the
	// transaction; an InTx inside fn joins it too.
	//
	// Work that goes on after fn (a goroutine started inside) is not part
	// of the transaction: once it ends, the queries made with that context
	// run on their own. What is not in the database (cache, e-mails, audit
	// entries written "best effort") goes after InTx, with the caller's
	// context. A repository error inside fn must end it: after a failed
	// statement the database refuses everything until the rollback.
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// NoTransaction runs fn as is: each write stands on its own. For stores
// without transactions (the in-memory fakes of the tests).
type NoTransaction struct{}

func (NoTransaction) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
