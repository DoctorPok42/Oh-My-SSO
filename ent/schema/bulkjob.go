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

// BulkJob is one bulk action of the admin console (a selection of users,
// sessions, clients... and one action on all of them). It runs in the
// background: this row is how every console and every idp-admin process
// follows it, and what is left of it when the server stops half-way.
//
// Like UserImportJob, it keeps no secret: an item is its id, the name shown
// for it and what became of it.
type BulkJob struct {
	ent.Schema
}

type BulkJobStatus string

const (
	BulkJobRunning   BulkJobStatus = "running"
	BulkJobCompleted BulkJobStatus = "completed" // every item was tried; some may have been skipped or failed
	// BulkJobInterrupted: the server stopped before the last item. The items
	// already done stay done; the others are listed as not run.
	BulkJobInterrupted BulkJobStatus = "interrupted"
)

// BulkJobItem is the outcome of one item.
type BulkJobItem struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func (BulkJob) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("action").NotEmpty().Immutable(),
		// Written in the audit entry of every item (details.operation_id).
		field.String("operation_id").NotEmpty().Immutable(),
		field.String("status").GoType(BulkJobStatus("")).Default(string(BulkJobRunning)),

		// Who started it: an administrator of the master realm. Not edges:
		// the report outlives the account.
		field.String("requested_by").NotEmpty().Immutable(),
		field.String("requested_by_name").NotEmpty().Immutable(),
		field.String("requested_by_realm").NotEmpty().Immutable(),

		// The selection, in the order it is done: what is left to do is
		// known even if the process dies without saying so.
		field.JSON("ids", []string{}).Immutable(),
		field.Int("total").Default(0).Immutable(),
		field.Int("processed").Default(0),
		field.Int("done_count").Default(0),
		field.Int("skipped_count").Default(0),
		field.Int("failed_count").Default(0),
		field.JSON("items", []BulkJobItem{}).Optional(),

		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		// Moves with the progress: a running job whose updated_at is old has
		// lost its process (see service.RunBulkReaper).
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("finished_at").Optional().Nillable(),
	}
}

func (BulkJob) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("bulk_jobs").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (BulkJob) Indexes() []ent.Index {
	return []ent.Index{
		// One running bulk action per realm, across every idp-admin process:
		// the guardrails of an item read the state the previous one left.
		index.Fields("realm_id").Unique().
			Annotations(entsql.IndexWhere("status = 'running'")),
		// The reaper's work list and the purge of old reports.
		index.Fields("status", "updated_at"),
	}
}
