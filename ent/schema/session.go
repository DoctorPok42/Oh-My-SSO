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

type Session struct {
	ent.Schema
}

type SessionStatus string

const (
	SessionActive  SessionStatus = "active"
	SessionExpired SessionStatus = "expired"
	SessionRevoked SessionStatus = "revoked"
)

// SessionAuthMethod values follow RFC 8176 (Authentication Method Reference
// Values), so the OIDC "amr" claim needs no translation.
type SessionAuthMethod string

const (
	SessionAuthPassword SessionAuthMethod = "pwd"
	SessionAuthMFA      SessionAuthMethod = "mfa"
)

type SessionRevokedReason string

const (
	SessionRevokedUserLogout     SessionRevokedReason = "user_logout"
	SessionRevokedAdminRevoked   SessionRevokedReason = "admin_revoked"
	SessionRevokedSecurityPolicy SessionRevokedReason = "security_policy"
	SessionRevokedExpired        SessionRevokedReason = "expired"
	SessionRevokedPasswordReset  SessionRevokedReason = "password_reset"
	SessionRevokedMFAReset       SessionRevokedReason = "mfa_reset"
	// Another account signed in in the same browser ("Use another account").
	SessionRevokedAccountSwitch SessionRevokedReason = "account_switch"
	// An administrator's timeout on the user, one of their groups or the
	// client started.
	SessionRevokedTimeout SessionRevokedReason = "timeout"
)

func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("user_id").NotEmpty().Immutable(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("expires_at"),
		field.Time("last_activity_at").Default(func() time.Time { return time.Now() }),
		field.String("ip_address").Optional(),
		field.String("user_agent").Optional(),
		field.String("device_fingerprint").Optional(),
		field.Bool("mfa_verified").Default(false),
		field.String("mfa_method_type").Optional(),
		// Last time a second factor was verified for this session (login or
		// step-up). Step-up checks compare it to the realm's
		// mfa_step_up_max_age_minutes.
		field.Time("mfa_verified_at").Optional(),
		field.String("auth_method").Default(string(SessionAuthPassword)),
		// The user ticked "Keep me signed in": the session follows the
		// realm's remember_me_* durations and its cookie survives a browser
		// restart. Otherwise the cookie is gone when the browser closes.
		field.Bool("remember_me").Default(false),
		// The second factor was skipped: the device is trusted ("Don't ask
		// again on this device") and no policy required MFA. Such a session
		// is never MFA-verified.
		field.Bool("trusted_device").Default(false),
		field.String("status").GoType(SessionStatus("")).Default(string(SessionActive)),
		field.String("revoked_reason").Optional(),
		field.String("token_hash").NotEmpty().Unique().Immutable().Sensitive(),
	}
}

func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("sessions").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.From("owner", User.Type).
			Ref("sessions").
			Field("user_id").
			Immutable().
			Unique().
			Required(),

		edge.To("tokens", Token.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "status"),
	}
}
