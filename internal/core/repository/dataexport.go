package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// DataExportRepository stores the personal data exports of the account
// console: one per user.
type DataExportRepository interface {
	// Start replaces the user's export with e (running), unless the current
	// one is running and was created after staleBefore: ErrConflict then.
	Start(ctx context.Context, e *domain.DataExport, staleBefore time.Time) error
	// Finish ends a running export: ready with its data, or failed (data
	// nil). An export replaced in the meantime is left alone.
	Finish(ctx context.Context, id string, status domain.DataExportStatus, data []byte, at, expiresAt time.Time) error
	// GetByUser returns the user's export without its data (Data nil: a
	// status page reads it often), ErrNotFound when there is none.
	GetByUser(ctx context.Context, userID string) (*domain.DataExport, error)
	// GetData returns the data of export id, ErrNotFound when it was
	// replaced or purged since.
	GetData(ctx context.Context, id string) ([]byte, error)
}
