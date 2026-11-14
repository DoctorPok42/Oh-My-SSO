package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// EmailVerificationToken is the link of an "is this your address?" e-mail.
// It is bound to the address it was sent to: if the account's address
// changes before the link is used, the link proves nothing and is refused.
// Like a reset link, only its SHA-256 is stored.
type EmailVerificationToken struct {
	ent.Schema
}

func (EmailVerificationToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("email").NotEmpty().Immutable(),
		field.String("token_hash").NotEmpty().Unique().Immutable(),
		field.Time("expires_at").Immutable(),
		field.Time("used_at").Optional().Nillable(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
	}
}

func (EmailVerificationToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("email_verification_tokens").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}
