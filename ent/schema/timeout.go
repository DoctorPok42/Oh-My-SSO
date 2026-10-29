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

// Timeout is a temporary suspension set by an administrator on a user, a
// group (every member) or a client. While it is in force, nobody it
// targets can sign in or get a token.
type Timeout struct {
	ent.Schema
}

type TimeoutTargetType string

const (
	TimeoutTargetUser      TimeoutTargetType = "user"
	TimeoutTargetGroup     TimeoutTargetType = "group"
	TimeoutTargetClientApp TimeoutTargetType = "client"
)

func (Timeout) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("target_type").GoType(TimeoutTargetType("")).Immutable(),
		field.String("target_id").NotEmpty().Immutable(),
		field.Time("starts_at").Immutable(),
		// Not set: no end, the timeout lasts until an administrator lifts it.
		field.Time("ends_at").Optional(),
		field.String("reason").NotEmpty(),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		// Set when an administrator ends the timeout early (ends_at then
		// moves to the same time). A lifted timeout is never in force again.
		field.Time("lifted_at").Optional(),
		field.String("lifted_by").Optional(),
		// When the targets were signed out (sessions and tokens revoked),
		// at the start of the timeout. Not set: not done yet.
		field.Time("enforced_at").Optional(),
	}
}

func (Timeout) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("timeouts").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (Timeout) Indexes() []ent.Index {
	return []ent.Index{
		// The check at every sign-in and token: by target.
		index.Fields("target_type", "target_id", "ends_at"),
		// The admin console's list of a realm.
		index.Fields("realm_id", "starts_at"),
		// The enforcer's work list: started timeouts whose targets are not
		// signed out yet. Partial: it stays tiny.
		index.Fields("starts_at").
			Annotations(entsql.IndexWhere("enforced_at IS NULL AND lifted_at IS NULL")),
	}
}
