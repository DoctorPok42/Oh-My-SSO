package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ApiResource is an API that accepts the realm's access tokens (RFC 8707).
// A client asks for a token meant for it with the "resource" parameter; the
// token's "aud" is then the identifier, and its scopes are those of the API.
type ApiResource struct {
	ent.Schema
}

func (ApiResource) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		// Identifier: an absolute URI without fragment, e.g.
		// "https://api.example.com" (RFC 8707, section 2). Immutable: the
		// API checks it in "aud", changing it would refuse every token.
		field.String("identifier").NotEmpty().Immutable(),
		field.String("name").NotEmpty(),
		field.String("description").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (ApiResource) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("api_resources").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
		// Scopes: the OIDC client scopes the API defines.
		edge.To("scopes", ClientScope.Type),
	}
}

func (ApiResource) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "identifier").Unique(),
	}
}
