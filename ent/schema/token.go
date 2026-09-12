package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type Token struct {
	ent.Schema
}

type TokenType string

const (
	TokenAccessToken  TokenType = "access_token"
	TokenRefreshToken TokenType = "refresh_token"
	TokenIDToken      TokenType = "id_token"
)

func (Token) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("session_id").NotEmpty().Immutable(),
		field.String("client_ref_id").NotEmpty().Immutable(),
		field.String("type").GoType(TokenType("")).Immutable(),
		field.String("jti").NotEmpty().Unique().Immutable(),
		field.Time("issued_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("expires_at").Immutable(),
		field.Bool("revoked").Default(false),
		field.JSON("scopes", []string{}).Optional(),
	}
}

func (Token) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("session", Session.Type).
			Ref("tokens").
			Field("session_id").
			Immutable().
			Unique().
			Required(),
		edge.From("client_app", ClientApp.Type).
			Ref("tokens").
			Field("client_ref_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (Token) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("session_id", "revoked"),
	}
}
