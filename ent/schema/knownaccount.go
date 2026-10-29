package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// KnownAccount is an account shown in "Pick an account" on one device: the
// user ticked "Keep me signed in" there. It survives sign-outs and stays
// until the user clicks "Forget" (or the account is deleted).
type KnownAccount struct {
	ent.Schema
}

func (KnownAccount) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("user_id").NotEmpty().Immutable(),
		// SHA-256 of the sso_device cookie (service.DeviceFingerprint), like
		// sessions.device_fingerprint: the cookie itself is never stored.
		field.String("device_hash").NotEmpty().Immutable().Sensitive(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		// Last sign-in with "Keep me signed in" on this device: newest first
		// in the picker, oldest dropped beyond the per-device limit.
		field.Time("last_used_at").Default(func() time.Time { return time.Now() }),
		// How the user likes to sign in on this device (Step 18e), set only
		// when they had a choice. last_method: "password" or "passkey", what
		// the tile starts with. last_second_factor: "passkey" or "totp",
		// what the second step starts with. Empty: the best one first.
		field.String("last_method").Optional(),
		field.String("last_second_factor").Optional(),
	}
}

func (KnownAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("known_accounts").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
		edge.From("user", User.Type).
			Ref("known_accounts").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (KnownAccount) Indexes() []ent.Index {
	return []ent.Index{
		// One tile per account and device; also serves "the accounts of
		// this device" (device_hash is the leading column).
		index.Fields("device_hash", "user_id").Unique(),
	}
}
