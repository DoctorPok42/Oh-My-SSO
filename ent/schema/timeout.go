package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

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
		field.Time("ends_at").Optional(),
		field.String("reason").NotEmpty(),
		field.String("created_by").NotEmpty().Immutable(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
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
		index.Fields("target_type", "target_id", "ends_at"),
	}
}
