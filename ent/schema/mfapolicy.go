package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// MfaPolicy is the MFA policy attached to a Role ("MFA Policies" screen of
// the admin panel, `mfaPolicies` in the config-as-code file).
//
// A user is subject to the policy of every active role they hold. Policies
// from the realm, the client and the roles combine: the strictest wins.
type MfaPolicy struct {
	ent.Schema
}

type MfaPolicyManagedBy string

const (
	MfaPolicyManagedByUI     MfaPolicyManagedBy = "ui"
	MfaPolicyManagedByConfig MfaPolicyManagedBy = "config"
)

func (MfaPolicy) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("role_id").NotEmpty().Immutable(),
		field.String("managed_by").GoType(MfaPolicyManagedBy("")).Default(string(MfaPolicyManagedByUI)),
		// required: holders of the role must pass a second factor at every
		// login, whatever the client.
		field.Bool("required").Default(false),
		// Methods that satisfy MFA for holders of the role. Empty: any.
		field.JSON("allowed_methods", []string{}).Optional(),
		// Days a holder without any allowed factor may still log in without
		// MFA, counted from required_since (or from the account creation
		// if the account is newer). 0 = no grace period.
		field.Int("enrollment_grace_days").Default(0).NonNegative(),
		// When true, sensitive actions (signing key rotation, ...) always
		// need a recent second factor for holders of the role: a recent
		// password login is not enough.
		field.Bool("step_up_for_sensitive_actions").Default(false),
		// Set when "required" goes from false to true: start of the grace
		// period. Cleared when "required" goes back to false.
		field.Time("required_since").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
	}
}

func (MfaPolicy) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("mfa_policies").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
		edge.From("role", Role.Type).
			Ref("mfa_policy").
			Field("role_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (MfaPolicy) Indexes() []ent.Index {
	// role_id is already unique: the role <-> policy edge is one-to-one.
	return []ent.Index{
		index.Fields("realm_id"),
	}
}
