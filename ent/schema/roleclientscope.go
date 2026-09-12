package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type RoleClientScope struct {
	ent.Schema
}

func (RoleClientScope) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("role_id").NotEmpty().Immutable(),
		field.String("client_scope_id").NotEmpty().Immutable(),
		field.Time("granted_at").Default(func() time.Time { return time.Now() }).Immutable(),
	}
}

func (RoleClientScope) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("role", Role.Type).
			Field("role_id").
			Immutable().
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("client_scope", ClientScope.Type).
			Field("client_scope_id").
			Immutable().
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
