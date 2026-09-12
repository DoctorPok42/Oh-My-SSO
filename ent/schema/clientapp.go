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

type ClientApp struct {
	ent.Schema
}

type ClientAppProtocol string

const (
	ClientAppProtocolOIDC  ClientAppProtocol = "oidc"
	ClientAppProtocolSAML2 ClientAppProtocol = "saml2"
)

type ClientAppStatus string

const (
	ClientAppActive    ClientAppStatus = "active"
	ClientAppInactive  ClientAppStatus = "inactive"
	ClientAppSuspended ClientAppStatus = "suspended"
)

type ClientAppManagedBy string

const (
	ClientAppManagedByUI     ClientAppManagedBy = "ui"
	ClientAppManagedByConfig ClientAppManagedBy = "config"
)

type ClientAppType string

const (
	ClientAppTypeConfidential ClientAppType = "confidential"
	ClientAppTypePublic       ClientAppType = "public"
)

func (ClientApp) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("managed_by").GoType(ClientAppManagedBy("")).Default(string(ClientAppManagedByUI)),
		field.String("name").NotEmpty(),
		field.String("protocol").NotEmpty().GoType(ClientAppProtocol("")).Immutable(),
		field.String("status").GoType(ClientAppStatus("")).Default(string(ClientAppActive)),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("deleted_at").Optional(),
		field.String("owner_admin_id").Optional(),

		// --- OIDC ---
		field.String("client_id").Optional(),
		field.String("client_secret_hash").Optional(),
		field.String("client_type").GoType(ClientAppType("")).Optional(),
		field.JSON("redirect_uris", []string{}).Optional(),
		field.JSON("post_logout_redirect_uris", []string{}).Optional(),
		field.JSON("allowed_grant_types", []string{}).Optional(),
		field.JSON("allowed_scopes", []string{}).Optional(),
		field.String("token_endpoint_auth_method").Optional(),
		field.String("id_token_signed_alg").Optional(),
		field.Int("access_token_ttl").Default(3600),
		field.Int("refresh_token_ttl").Default(2592000),
		field.Int("id_token_ttl").Default(3600),
		field.Bool("require_pkce").Default(true),

		// --- SAML ---
		field.String("entity_id").Optional(),
		field.String("acs_url").Optional(),
		field.String("slo_url").Optional(),
		field.JSON("client_certificates", []map[string]interface{}{}).Optional(),
		field.String("name_id_format").Optional(),
		field.Bool("want_assertion_signed").Default(true),
		field.Bool("want_response_signed").Default(false),
		field.String("default_relay_state").Optional(),

		// --- Common ---
		field.JSON("attribute_mappings", map[string]interface{}{}).Optional(),
		field.Bool("require_consent").Default(false),
		field.String("metadata_url").Optional(),
	}
}

func (ClientApp) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("client_apps").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.From("roles", Role.Type).
			Ref("client_apps").
			Through("client_roles", ClientRole.Type),
		edge.From("groups", Group.Type).
			Ref("client_apps").
			Through("client_groups", ClientGroup.Type),
		edge.To("client_scopes", ClientScope.Type).
			Through("client_scope_mappings", ClientScopeMapping.Type),

		edge.To("tokens", Token.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("consents", Consent.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

func (ClientApp) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "client_id").Unique(),
		index.Fields("realm_id", "entity_id").Unique(),
	}
}
