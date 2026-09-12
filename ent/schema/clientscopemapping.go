package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type ClientScopeMapping struct {
	ent.Schema
}

func (ClientScopeMapping) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("client_app_id").NotEmpty().Immutable(),
		field.String("client_scope_id").NotEmpty().Immutable(),
		field.Bool("required").Default(false),
	}
}

func (ClientScopeMapping) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("client_app", ClientApp.Type).
			Field("client_app_id").
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
