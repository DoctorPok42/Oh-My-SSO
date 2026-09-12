package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type FederatedIdentity struct {
	ent.Schema
}

func (FederatedIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("identity_provider_id").NotEmpty().Immutable(),
		field.String("external_subject").NotEmpty().Immutable(),
		field.Time("linked_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("last_login_at").Optional(),
	}
}

func (FederatedIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("federated_identities").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
		edge.From("identity_provider", IdentityProvider.Type).
			Ref("federated_identities").
			Field("identity_provider_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (FederatedIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("identity_provider_id", "external_subject").Unique(),
	}
}
