package domain

import "time"

type DataExportStatus string

const (
	DataExportRunning DataExportStatus = "running"
	DataExportReady   DataExportStatus = "ready"
	DataExportFailed  DataExportStatus = "failed"
)

// DataExport is a copy of what the server keeps about a user (account
// console, "Your data"): made in the background, downloadable until
// ExpiresAt, then purged.
type DataExport struct {
	ID         string
	RealmID    string
	UserID     string
	Status     DataExportStatus
	Data       []byte // the JSON document, once ready
	CreatedAt  time.Time
	FinishedAt *time.Time
	ExpiresAt  time.Time
}
