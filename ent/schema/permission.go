package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type Permission struct {
	ent.Schema
}

type PermissionStatus string

const (
	PermissionActive   PermissionStatus = "active"
	PermissionInactive PermissionStatus = "inactive"
)

func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("name").NotEmpty(),
		field.String("description").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.String("status").GoType(PermissionStatus("")).Default(string(PermissionActive)),
		field.String("resource").NotEmpty(),
		field.String("action").NotEmpty(),
		field.String("scope").NotEmpty(),
		field.JSON("constraints", map[string]interface{}{}).Optional(),
	}
}

func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("permissions").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.From("roles", Role.Type).Ref("permissions"),
		edge.From("groups", Group.Type).Ref("permissions"),
	}
}

func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "name").Unique(),
	}
}
