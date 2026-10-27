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

type User struct {
	ent.Schema
}

type UserStatus string

const (
	UserActive    UserStatus = "active"
	UserInactive  UserStatus = "inactive"
	UserSuspended UserStatus = "suspended"
)

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("username").NotEmpty(),
		field.String("password_hash").Optional(),
		field.String("email").NotEmpty(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("deleted_at").Optional().Nillable(),
		field.String("status").GoType(UserStatus("")).Default(string(UserActive)),
		field.Time("last_login_at").Optional().Nillable(),
		field.JSON("profile", map[string]interface{}{}).Optional(),

		field.Int("failed_login_count").Default(0),
		field.Time("last_failed_login_at").Optional().Nillable(),
		field.Time("locked_until").Optional().Nillable(),
		// Locks in a row, for the progressive lockout: each new lock within
		// 24 h of the previous one lasts twice as long (capped at 24 h).
		// Back to 0 after a successful login, an unlock or a password reset.
		field.Int("lockout_count").Default(0),
		field.Time("last_locked_at").Optional().Nillable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("users").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.To("roles", Role.Type),
		edge.To("groups", Group.Type),

		edge.To("sessions", Session.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("mfa_methods", MfaMethod.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("mfa_backup_codes", MfaBackupCode.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("password_reset_tokens", PasswordResetToken.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("known_accounts", KnownAccount.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("consents", Consent.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("federated_identities", FederatedIdentity.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "username").Unique(),
		index.Fields("realm_id", "email").Unique(),
	}
}
