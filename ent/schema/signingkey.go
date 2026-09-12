package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type SigningKey struct {
	ent.Schema
}

type SigningKeyType string

const (
	SigningKeyRSA SigningKeyType = "RSA"
	SigningKeyEC  SigningKeyType = "EC"
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
