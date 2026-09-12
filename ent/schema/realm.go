package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type Realm struct {
	ent.Schema
}

type RealmStatus string

const (
	RealmActive   RealmStatus = "active"
	RealmInactive RealmStatus = "inactive"
)

func (Realm) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("name").NotEmpty().Unique(),
		field.Bool("is_system_realm").Default(false).Immutable(),
		field.String("display_name").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.String("status").GoType(RealmStatus("")).Default(string(RealmActive)),
	}
}

func (Realm) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("users", User.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("roles", Role.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("groups", Group.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("permissions", Permission.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("client_scopes", ClientScope.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("client_apps", ClientApp.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("sessions", Session.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("signing_keys", SigningKey.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("audit_logs", AuditLog.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("identity_providers", IdentityProvider.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("instance_settings", InstanceSettings.Type).Unique().Annotations(entsql.OnDelete(entsql.Restrict)),
		edge.To("timeouts", Timeout.Type).Annotations(entsql.OnDelete(entsql.Restrict)),
	}
}
