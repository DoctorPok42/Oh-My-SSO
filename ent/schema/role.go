package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type Role struct {
	ent.Schema
}

type RoleStatus string

const (
	RoleActive   RoleStatus = "active"
	RoleInactive RoleStatus = "inactive"
)

type RoleManagedBy string

const (
	RoleManagedByUI     RoleManagedBy = "ui"
	RoleManagedByConfig RoleManagedBy = "config"
)

func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("managed_by").GoType(RoleManagedBy("")).Default(string(RoleManagedByUI)),
		field.String("name").NotEmpty(),
		field.String("description").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.String("status").GoType(RoleStatus("")).Default(string(RoleActive)),
	}
}

func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("roles").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.From("users", User.Type).Ref("roles"),
		edge.To("permissions", Permission.Type),
		edge.To("client_scopes", ClientScope.Type).
			Through("role_client_scopes", RoleClientScope.Type),
		edge.To("client_apps", ClientApp.Type).
			Through("client_roles", ClientRole.Type),
	}
}

func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "name").Unique(),
	}
}
