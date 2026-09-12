package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type Group struct {
	ent.Schema
}

type GroupStatus string

const (
	GroupActive   GroupStatus = "active"
	GroupInactive GroupStatus = "inactive"
)

type GroupManagedBy string

const (
	GroupManagedByUI     GroupManagedBy = "ui"
	GroupManagedByConfig GroupManagedBy = "config"
)

func (Group) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("managed_by").GoType(GroupManagedBy("")).Default(string(GroupManagedByUI)),
		field.String("name").NotEmpty(),
		field.String("description").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.String("status").GoType(GroupStatus("")).Default(string(GroupActive)),
	}
}

func (Group) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("groups").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.From("users", User.Type).Ref("groups"),

		edge.To("permissions", Permission.Type),

		edge.To("client_scopes", ClientScope.Type).
			Through("group_client_scopes", GroupClientScope.Type),
		edge.To("client_apps", ClientApp.Type).
			Through("client_groups", ClientGroup.Type),
	}
}

func (Group) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "name").Unique(),
	}
}
