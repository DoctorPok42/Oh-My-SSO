package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type KeyRotationLog struct {
	ent.Schema
}

type KeyRotationAction string

const (
	KeyRotationCreated     KeyRotationAction = "created"
	KeyRotationRotated     KeyRotationAction = "rotated"
	KeyRotationRetired     KeyRotationAction = "retired"
	KeyRotationCompromised KeyRotationAction = "compromised"
	KeyRotationDeleted     KeyRotationAction = "deleted"
)

func (KeyRotationLog) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("signing_key_id").NotEmpty().Immutable(),
		field.String("action").GoType(KeyRotationAction("")).Immutable(),
		field.String("triggered_by").NotEmpty().Immutable(),
		field.String("reason").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
	}
}

func (KeyRotationLog) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("signing_key", SigningKey.Type).
			Ref("rotation_logs").
			Field("signing_key_id").
			Immutable().
			Unique().
			Required(),
	}
}
