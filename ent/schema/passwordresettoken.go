package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type PasswordResetToken struct {
	ent.Schema
}

func (PasswordResetToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("token_hash").NotEmpty().Unique().Immutable(),
		field.Time("expires_at").Immutable(),
		field.Bool("used").Default(false),
		field.Time("used_at").Optional(),
		field.String("requested_ip").Optional().Immutable(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (PasswordResetToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("password_reset_tokens").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}
