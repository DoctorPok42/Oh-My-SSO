package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
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
	// MfaMethodPending is a factor whose enrollment was started but not
	// confirmed yet (e.g. a TOTP secret shown as a QR code, waiting for a
	// first valid code). It can never be used to log in.
	MfaMethodPending  MfaMethodStatus = "pending"
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
		// Label chosen by the user ("iPhone de Julie"), shown in the
		// account console. Never used for any security decision.
		field.String("name").Optional().MaxLen(100),
		// TOTP only: envelope-encrypted secret (see service/envelope.go).
		field.Text("secret_encrypted").Optional().Sensitive(),
		// WebAuthn / passkey: credential id (base64url) and COSE public key
		// (base64), kept for display and lookups. The full credential record
		// (sign counter, flags, transports...) is in webauthn_credential.
		field.String("credential_id").Optional(),
		field.Text("public_key").Optional(),
		// WebAuthn / passkey: the credential record as JSON, exactly as the
		// go-webauthn library needs it back at each login (Step 9b).
		field.Text("webauthn_credential").Optional(),
		field.Bool("is_discoverable").Default(false),
		field.String("status").GoType(MfaMethodStatus("")).Default(string(MfaMethodActive)),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("last_used_at").Optional(),
		// TOTP only: time-step counter (unix time / 30) of the last accepted
		// code. A code is accepted only if its counter is strictly greater,
		// so the same code can never be used twice (RFC 6238 §5.2).
		field.Int64("last_used_counter").Default(0),
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
		// A WebAuthn credential id is globally unique: the same authenticator
		// credential can never be registered twice (or for two users).
		index.Fields("credential_id").Unique(),
		// At most one ACTIVE TOTP per user (partial unique index). Pending
		// enrollments are not concerned, so a user can enroll a new phone
		// while the old one still works; the swap happens in one
		// transaction when the new one is confirmed.
		index.Fields("user_id").
			Unique().
			StorageKey("mfamethod_user_id_active_totp").
			Annotations(entsql.IndexWhere("type = 'totp' AND status = 'active'")),
	}
}
