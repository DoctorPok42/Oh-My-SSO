package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// UserImportRepository stores the imports of CSV files of users.
type UserImportRepository interface {
	// Create records a running import. ErrConflict: this realm already has one.
	Create(ctx context.Context, p CreateUserImportParams) (*domain.UserImportJob, error)
	GetByID(ctx context.Context, id string) (*domain.UserImportJob, error)
	// ListByRealm returns the newest imports of a realm, without their rows.
	ListByRealm(ctx context.Context, realmID string, limit int) ([]*domain.UserImportJob, error)
	// UpdateProgress saves where a running import stands, which also proves
	// that its process is alive. Without Rows, the saved rows stay as they are.
	UpdateProgress(ctx context.Context, id string, p UserImportProgress) error
	// Finish ends a running import. false: it was no longer running.
	Finish(ctx context.Context, id string, status domain.UserImportStatus, p UserImportProgress, at time.Time) (bool, error)
	// ReapStale ends, as interrupted, the imports still running whose last
	// progress is older than before, and returns those it ended (several
	// processes can reap at once: each import is returned to one of them).
	ReapStale(ctx context.Context, before, at time.Time) ([]*domain.UserImportJob, error)
	// DeleteFinishedBefore removes the reports older than before.
	DeleteFinishedBefore(ctx context.Context, before time.Time) (int, error)
}

// CreateUserImportParams: what is known when an import starts.
type CreateUserImportParams struct {
	RealmID          string
	FileName         string
	RequestedBy      string
	RequestedByName  string
	RequestedByRealm string
	SendEmail        bool
	NotifyWhenDone   bool
	Total            int
	IgnoredColumns   []string
}

// UserImportProgress: the lines done so far.
type UserImportProgress struct {
	Processed int
	Created   int
	Failed    int
	Rows      []domain.UserImportRow
}
