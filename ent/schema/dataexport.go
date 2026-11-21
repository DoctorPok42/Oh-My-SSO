package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// DataExport is a copy of what the server keeps about a user, asked for in
// the account console ("Your data", GDPR articles 15 and 20). It is made in
// the background, kept for download until expires_at, then purged. One per
// user: a new request replaces the previous one.
type DataExport struct {
	ent.Schema
}

type DataExportStatus string

const (
	DataExportRunning DataExportStatus = "running"
	DataExportReady   DataExportStatus = "ready"
	DataExportFailed  DataExportStatus = "failed"
)

func (DataExport) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("status").GoType(DataExportStatus("")).Default(string(DataExportRunning)),
		// The JSON document, once ready.
		field.Bytes("data").Optional().Sensitive(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("finished_at").Optional().Nillable(),
		// Always set, also while running: the purge deletes any export past
		// it, one stuck by a server that stopped included.
		field.Time("expires_at"),
	}
}

func (DataExport) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("data_exports").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (DataExport) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id").Unique(),
		index.Fields("expires_at"),
	}
}
