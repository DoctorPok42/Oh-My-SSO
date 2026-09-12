package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type Consent struct {
	ent.Schema
}

type ConsentStatus string

const (
	ConsentGranted ConsentStatus = "granted"
	ConsentRevoked ConsentStatus = "revoked"
)

func (Consent) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("client_ref_id").NotEmpty().Immutable(),
		field.JSON("scopes", []string{}).Optional(),
		field.String("status").GoType(ConsentStatus("")).Default(string(ConsentGranted)),
		field.Time("granted_at").Default(func() time.Time { return time.Now() }),
		field.Time("revoked_at").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (Consent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("consents").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
		edge.From("client_app", ClientApp.Type).
			Ref("consents").
			Field("client_ref_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (Consent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_ref_id").Unique(),
	}
}
