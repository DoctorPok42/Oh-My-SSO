package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type ClientRole struct {
	ent.Schema
}

func (ClientRole) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("client_app_id").NotEmpty().Immutable(),
		field.String("role_id").NotEmpty().Immutable(),
		field.Time("granted_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.String("granted_by").Optional(),
	}
}

func (ClientRole) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("client_app", ClientApp.Type).
			Field("client_app_id").
			Immutable().
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("role", Role.Type).
			Field("role_id").
			Immutable().
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
