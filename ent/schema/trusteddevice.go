package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TrustedDevice: the user ticked "Don't ask again on this device" after a
// second factor. Until expires_at, a password alone signs them in there
// when no policy requires MFA. It ends at expires_at, with "Forget" on the
// device's tile, or when every session of the user is revoked.
type TrustedDevice struct {
	ent.Schema
}

func (TrustedDevice) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("user_id").NotEmpty().Immutable(),
		// SHA-256 of the sso_device cookie, like known_accounts.device_hash.
		field.String("device_hash").NotEmpty().Immutable().Sensitive(),
		// Where the box was ticked, and the last sign-in that used the trust
		// (shown to admins as "Firefox on Windows", 203.0.113.7).
		field.String("ip_address").Optional(),
		field.String("user_agent").Optional(),
		// When the box was ticked. Ticking it again starts a new period (both
		// dates move); using the trust does not extend it.
		field.Time("created_at").Default(func() time.Time { return time.Now() }),
		field.Time("expires_at"),
		field.Time("last_used_at").Optional().Nillable(),
	}
}

func (TrustedDevice) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("trusted_devices").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
		edge.From("user", User.Type).
			Ref("trusted_devices").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (TrustedDevice) Indexes() []ent.Index {
	return []ent.Index{
		// One trust per account and device ("Forget" looks it up this way).
		index.Fields("device_hash", "user_id").Unique(),
		// The devices of a user (admin console, revocation).
		index.Fields("user_id"),
	}
}
