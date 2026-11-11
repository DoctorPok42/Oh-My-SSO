package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// BulkJobRepository stores the bulk actions of the admin console.
type BulkJobRepository interface {
	// Create records a running bulk action. ErrConflict: this realm already
	// has one.
	Create(ctx context.Context, p CreateBulkJobParams) (*domain.BulkJob, error)
	GetByID(ctx context.Context, id string) (*domain.BulkJob, error)
	// UpdateProgress saves where a running bulk action stands, which also
	// proves that its process is alive. Without Items, the saved items stay
	// as they are.
	UpdateProgress(ctx context.Context, id string, p BulkJobProgress) error
	// Finish ends a running bulk action. false: it was no longer running.
	Finish(ctx context.Context, id string, status domain.BulkJobStatus, p BulkJobProgress, at time.Time) (bool, error)
	// ReapStale ends, as interrupted, the bulk actions still running whose
	// last progress is older than before, and returns those it ended
	// (several processes can reap at once: each one is returned to one of
	// them).
	ReapStale(ctx context.Context, before, at time.Time) ([]*domain.BulkJob, error)
	// SaveItems replaces the items of a bulk action that is over.
	SaveItems(ctx context.Context, id string, items []domain.BulkItem) error
	// DeleteFinishedBefore removes the reports older than before.
	DeleteFinishedBefore(ctx context.Context, before time.Time) (int, error)
}

// CreateBulkJobParams: what is known when a bulk action starts.
type CreateBulkJobParams struct {
	RealmID          string
	Action           string
	OperationID      string
	RequestedBy      string
	RequestedByName  string
	RequestedByRealm string
	IDs              []string
}

// BulkJobProgress: the items done so far.
type BulkJobProgress struct {
	Processed int
	Done      int
	Skipped   int
	Failed    int
	Items     []domain.BulkItem
}
