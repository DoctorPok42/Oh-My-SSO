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
		// "Keep me signed in" on the sign-in page. A remembered session
		// lasts remember_me_max_days at most and ends after
		// remember_me_idle_days without use. Off in the master realm (set
		// by its bootstrap and by the migration that added these columns).
		field.Bool("remember_me_enabled").Default(true),
		field.Int("remember_me_idle_days").Default(7),
		field.Int("remember_me_max_days").Default(30),
		field.Int("lockout_threshold").Default(5),
		field.Int("lockout_duration_minutes").Default(15),
		field.JSON("ip_allowlist", []string{}).Optional(),
		field.Bool("mfa_required_globally").Default(false),
		field.Bool("notification_email_enabled").Default(false),
		// Grace period of a rotated signing key: how long the old public key
		// stays in the JWKS so tokens it signed can still be verified. Must
		// be longer than the longest token lifetime plus the JWKS cache time.
		field.Int("key_rotation_grace_hours").Default(24),
		// How long a second-factor verification counts as "recent" for
		// sensitive actions (step-up), e.g. rotating a signing key or
		// removing an MFA factor.
		field.Int("mfa_step_up_max_age_minutes").Default(10),
		// "Don't ask again on this device": after a second factor, the user
		// may skip it on that device for mfa_trusted_device_days (1 to 90),
		// when no policy requires MFA. Off in the master realm (bootstrap
		// and the migration that added these columns).
		field.Bool("mfa_trusted_device_enabled").Default(true),
		field.Int("mfa_trusted_device_days").Default(30),
		field.Int("password_reset_ttl_minutes").Default(30),
		// How long an invitation / activation link stays valid.
		field.Int("invite_ttl_hours").Default(4),
		field.Bool("suspicious_login_email_enabled").Default(false),
		// Language of the sign-in pages and e-mails when the user has not
		// chosen one (package i18n): "en", or a language with a translation
		// file.
		field.String("default_locale").Default("en"),
		// Sender of the realm's e-mails. Empty = the server's SMTP_FROM.
		// mail_from_address must be an address the SMTP server may send
		// from (SPF/DKIM); mail_logo_url is an https image shown in the
		// header of every e-mail.
		field.String("mail_from_name").Default(""),
		field.String("mail_from_address").Default(""),
		field.String("mail_reply_to").Default(""),
		field.String("mail_logo_url").Default(""),
		// The most items one bulk action of the admin console may touch
		// (1 to 500). A larger selection is done in several passes, so a
		// mistake stays small.
		field.Int("bulk_limit").Default(100),
		// How long data that has ended is kept before it is deleted (7 to
		// 3650 days): sessions and tokens after they expired or were
		// revoked, used or expired reset / activation links, sign-in
		// attempts, accounts of "Pick an account" and trusted devices
		// unused for that long. 90 days: the history the suspicious
		// sign-in check looks at.
		field.Int("expired_data_retention_days").Default(90),
		// How long the entries of the audit log are kept before they are
		// deleted (30 to 3650 days); 0 keeps them forever. One year by
		// default (service.DefaultAuditLogRetentionDays).
		field.Int("audit_log_retention_days").Default(365),
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
