package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type MfaMethod struct {
	ent.Schema
}

type MfaMethodType string

const (
	MfaMethodTOTP        MfaMethodType = "totp"
	MfaMethodWebAuthn    MfaMethodType = "webauthn"
	MfaMethodPasskey     MfaMethodType = "passkey"
	MfaMethodBackupCodes MfaMethodType = "backup_codes"
	MfaMethodBiometric   MfaMethodType = "biometric"
)

type MfaMethodStatus string

const (
	MfaMethodActive   MfaMethodStatus = "active"
	MfaMethodDisabled MfaMethodStatus = "disabled"
)

func (MfaMethod) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("user_id").NotEmpty().Immutable(),
		field.String("type").GoType(MfaMethodType("")).Immutable(),
		field.Text("secret_encrypted").Optional(),
		field.String("credential_id").Optional(),
		field.Text("public_key").Optional(),
		field.Bool("is_discoverable").Default(false),
		field.String("status").GoType(MfaMethodStatus("")).Default(string(MfaMethodActive)),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("last_used_at").Optional(),
	}
}

func (MfaMethod) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("mfa_methods").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (MfaMethod) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "type"),
	}
}
