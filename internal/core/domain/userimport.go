package domain

import "time"

// UserImportStatus: where an import of a CSV file of users stands.
type UserImportStatus string

const (
	UserImportRunning   UserImportStatus = "running"
	UserImportCompleted UserImportStatus = "completed" // every line was tried; some may have failed
	// UserImportInterrupted: the server stopped before the last line. The
	// lines already done stay done.
	UserImportInterrupted UserImportStatus = "interrupted"
)

// Outcomes of a line of the file.
const (
	UserImportRowCreated = "created"
	UserImportRowFailed  = "failed"
)

// UserImportRow is the outcome of one line.
type UserImportRow struct {
	Line     int    `json:"line"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	UserID   string `json:"-"` // what the activation links are issued from
	Emailed  bool   `json:"emailed"`
	// What the account received: the import's audit entry lists it.
	Groups []string `json:"-"`
	Roles  []string `json:"-"`
}

// UserImportJob is an import running in the background, or its report.
type UserImportJob struct {
	ID               string
	RealmID          string
	Status           UserImportStatus
	FileName         string
	RequestedBy      string // user id, in RequestedByRealm
	RequestedByName  string
	RequestedByRealm string
	SendEmail        bool
	NotifyWhenDone   bool
	Total            int
	Processed        int
	Created          int
	Failed           int
	IgnoredColumns   []string
	Rows             []UserImportRow
	CreatedAt        time.Time
	UpdatedAt        time.Time
	FinishedAt       *time.Time
}
