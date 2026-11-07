package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// UserImportJob is one import of a CSV file of users (Users page of the
// admin console). The file runs in the background: this row is how every
// console and every idp-admin process follows it.
//
// The file itself is not kept. Neither are activation links: the database
// only ever holds the hash of a token, so the links of an import made
// without e-mails are issued when an administrator asks for them.
type UserImportJob struct {
	ent.Schema
}

type UserImportStatus string

const (
	UserImportRunning   UserImportStatus = "running"
	UserImportCompleted UserImportStatus = "completed" // every line was tried; some may have failed
	// UserImportInterrupted: the server stopped before the last line. The
	// lines already done stay done.
	UserImportInterrupted UserImportStatus = "interrupted"
)

// UserImportRow is the outcome of one line of the file. It never holds
// anything else from that line: the report stays free of what a file may
// carry by mistake.
type UserImportRow struct {
	Line     int    `json:"line"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	Emailed  bool   `json:"emailed,omitempty"`
	// Names, for the audit entry at the end of the import.
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

func (UserImportJob) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("status").GoType(UserImportStatus("")).Default(string(UserImportRunning)),
		field.String("file_name").Default("").Immutable(),

		// Who started it: an administrator of the master realm. Not edges:
		// the report outlives the account.
		field.String("requested_by").NotEmpty().Immutable(),
		field.String("requested_by_name").NotEmpty().Immutable(),
		field.String("requested_by_realm").NotEmpty().Immutable(),

		field.Bool("send_email").Default(false).Immutable(),
		field.Bool("notify_when_done").Default(false).Immutable(),

		field.Int("total").Default(0).Immutable(),
		field.Int("processed").Default(0),
		field.Int("created_count").Default(0),
		field.Int("failed_count").Default(0),
		field.Strings("ignored_columns").Optional().Immutable(),
		field.JSON("rows", []UserImportRow{}).Optional(),

		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		// Moves with the progress: a running job whose updated_at is old has
		// lost its process (see service.RunUserImportReaper).
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("finished_at").Optional().Nillable(),
	}
}

func (UserImportJob) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("user_import_jobs").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (UserImportJob) Indexes() []ent.Index {
	return []ent.Index{
		// The list of a realm, the newest first.
		index.Fields("realm_id", "created_at"),
		// One running import per realm, across every idp-admin process.
		index.Fields("realm_id").Unique().
			Annotations(entsql.IndexWhere("status = 'running'")),
		// The reaper's work list and the purge of old reports.
		index.Fields("status", "updated_at"),
	}
}
