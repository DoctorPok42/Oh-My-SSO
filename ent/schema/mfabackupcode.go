package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type MfaBackupCode struct {
	ent.Schema
}

func (MfaBackupCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("batch_id").NotEmpty().Immutable(),
		field.String("code_hash").NotEmpty().Immutable(),
		field.Bool("used").Default(false),
		field.Time("used_at").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (MfaBackupCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("mfa_backup_codes").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (MfaBackupCode) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "batch_id"),
		index.Fields("code_hash"),
	}
}
