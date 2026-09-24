package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

type InstanceSettings struct {
	ent.Schema
}

type InstanceSettingsManagedBy string

const (
	InstanceSettingsManagedByUI     InstanceSettingsManagedBy = "ui"
	InstanceSettingsManagedByConfig InstanceSettingsManagedBy = "config"
)

func (InstanceSettings) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("managed_by").GoType(InstanceSettingsManagedBy("")).Default(string(InstanceSettingsManagedByUI)),
		field.Int("min_password_length").Default(12),
		field.Int("password_expiry_days").Default(90),
		field.Int("session_idle_minutes").Default(10),
		field.Int("session_max_hours").Default(8),
		field.Int("lockout_threshold").Default(5),
		field.Int("lockout_duration_minutes").Default(15),
		field.JSON("ip_allowlist", []string{}).Optional(),
		field.Bool("mfa_required_globally").Default(false),
		field.Bool("notification_email_enabled").Default(false),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.String("updated_by").Optional(),
	}
}

func (InstanceSettings) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("instance_settings").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
	}
}
