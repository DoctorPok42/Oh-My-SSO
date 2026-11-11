package domain

import "time"

// BulkJobStatus: where a bulk action of the admin console stands.
type BulkJobStatus string

const (
	BulkJobRunning   BulkJobStatus = "running"
	BulkJobCompleted BulkJobStatus = "completed" // every item was tried; some may have been skipped or failed
	// BulkJobInterrupted: the server stopped before the last item. The items
	// already done stay done; the others are listed as not run.
	BulkJobInterrupted BulkJobStatus = "interrupted"
)

// What became of one item of a bulk action.
const (
	BulkItemDone    = "done"
	BulkItemSkipped = "skipped" // a guardrail or nothing to do: the sentence says why
	BulkItemFailed  = "failed"  // a server problem: logged, never shown
	// BulkItemNotRun: the server stopped before this item.
	BulkItemNotRun = "not_run"
	// BulkItemUnknown: the process died while it was working on this item,
	// or just after: only the audit log of the operation tells.
	BulkItemUnknown = "unknown"
)

// BulkItem is the outcome of one item.
type BulkItem struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// BulkJob is a bulk action running in the background, or its report.
type BulkJob struct {
	ID               string
	RealmID          string
	Action           string
	OperationID      string
	Status           BulkJobStatus
	RequestedBy      string // user id, in RequestedByRealm
	RequestedByName  string
	RequestedByRealm string
	// IDs is the selection, in the order it is done.
	IDs        []string
	Total      int
	Processed  int
	Done       int
	Skipped    int
	Failed     int
	Items      []BulkItem
	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt *time.Time
}
