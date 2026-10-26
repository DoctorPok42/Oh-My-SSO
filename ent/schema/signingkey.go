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

type SigningKey struct {
	ent.Schema
}

type SigningKeyType string

const (
	SigningKeyRSA SigningKeyType = "RSA"
	SigningKeyEC  SigningKeyType = "EC"
	// SigningKeyAES is a symmetric key, only used with the
	// envelope_encryption purpose (it has no public part).
	SigningKeyAES SigningKeyType = "AES"
)

type SigningKeyPurpose string

const (
	SigningKeyPurposeJWT             SigningKeyPurpose = "jwt_signing"
	SigningKeyPurposeSAMLSigning     SigningKeyPurpose = "saml_signing"
	SigningKeyPurposeSAMLEncryption  SigningKeyPurpose = "saml_encryption"
	SigningKeyPurposeEnvelopeEncrypt SigningKeyPurpose = "envelope_encryption"
)

type SigningKeyStatus string

const (
	SigningKeyPending  SigningKeyStatus = "pending"
	SigningKeyActive   SigningKeyStatus = "active"
	SigningKeyRotating SigningKeyStatus = "rotating"
	SigningKeyRetired  SigningKeyStatus = "retired"
)

func (SigningKey) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("key_type").GoType(SigningKeyType("")).Immutable(),
		field.String("purpose").GoType(SigningKeyPurpose("")).Immutable(),
		field.String("kms_key_reference").NotEmpty().Immutable(),
		field.String("kms_backend").NotEmpty().Immutable(),
		field.Text("public_key").Optional(),
		field.String("kid").NotEmpty().Unique().Immutable(),
		field.String("status").GoType(SigningKeyStatus("")).Default(string(SigningKeyActive)),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("retired_at").Optional(),
		// retire_after is the end of the grace period of a "rotating" key.
		// It is set once, when the key leaves "active", from the realm's
		// key_rotation_grace_hours. Storing the deadline on the key (instead
		// of recomputing it) means changing the realm setting later never
		// shortens the grace period of a key that is already rotating.
		field.Time("retire_after").Optional(),
		field.Text("certificate").Optional().Immutable(),
	}
}

func (SigningKey) Indexes() []ent.Index {
	return []ent.Index{
		// JWKS endpoint and Signer: "keys of this realm, for this purpose,
		// with this status". Without it, every JWKS request scans the table.
		index.Fields("realm_id", "purpose", "status"),
	}
}

func (SigningKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("signing_keys").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.To("rotation_logs", KeyRotationLog.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
	}
}
