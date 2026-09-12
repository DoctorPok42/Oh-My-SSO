package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type ClientScope struct {
	ent.Schema
}

type ClientScopeProtocol string

const (
	ClientScopeProtocolOIDC  ClientScopeProtocol = "oidc"
	ClientScopeProtocolSAML2 ClientScopeProtocol = "saml2"
	ClientScopeProtocolBoth  ClientScopeProtocol = "both"
)

func (ClientScope) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("name").NotEmpty(),
		field.String("description").Optional(),
		field.String("protocol").NotEmpty().Default(string(ClientScopeProtocolOIDC)).GoType(ClientScopeProtocol("")),
		field.Bool("is_default").Default(false),
		field.JSON("claim_mappers", []map[string]interface{}{}).Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (ClientScope) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("client_scopes").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.From("roles", Role.Type).
			Ref("client_scopes").
			Through("role_client_scopes", RoleClientScope.Type),
		edge.From("groups", Group.Type).
			Ref("client_scopes").
			Through("group_client_scopes", GroupClientScope.Type),
		edge.From("client_apps", ClientApp.Type).
			Ref("client_scopes").
			Through("client_scope_mappings", ClientScopeMapping.Type),
	}
}

func (ClientScope) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "name").Unique(),
	}
}
