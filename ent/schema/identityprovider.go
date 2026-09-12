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

type IdentityProvider struct {
	ent.Schema
}

type IdentityProviderProtocol string

const (
	IdentityProviderOIDC  IdentityProviderProtocol = "oidc"
	IdentityProviderSAML2 IdentityProviderProtocol = "saml2"
)

type IdentityProviderStatus string

const (
	IdentityProviderActive   IdentityProviderStatus = "active"
	IdentityProviderInactive IdentityProviderStatus = "inactive"
)

type IdentityProviderManagedBy string

const (
	IdentityProviderManagedByUI     IdentityProviderManagedBy = "ui"
	IdentityProviderManagedByConfig IdentityProviderManagedBy = "config"
)

func (IdentityProvider) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("managed_by").GoType(IdentityProviderManagedBy("")).Default(string(IdentityProviderManagedByUI)),
		field.String("name").NotEmpty(),
		field.String("protocol").GoType(IdentityProviderProtocol("")).Immutable(),
		field.String("status").GoType(IdentityProviderStatus("")).Default(string(IdentityProviderActive)),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),

		// --- OIDC ---
		field.String("issuer_url").Optional(),
		field.String("client_id").Optional(),
		field.String("client_secret_hash").Optional(),
		field.String("authorization_endpoint").Optional(),
		field.String("token_endpoint").Optional(),
		field.String("userinfo_endpoint").Optional(),
		field.String("jwks_uri").Optional(),
		field.JSON("scopes_requested", []string{}).Optional(),

		// --- SAML2 ---
		field.String("idp_entity_id").Optional(),
		field.String("idp_sso_url").Optional(),
		field.Text("idp_certificate").Optional(),

		// --- Common ---
		field.JSON("attribute_mapping", map[string]interface{}{}).Optional(),
		field.Bool("auto_provisioning").Default(false),
		field.JSON("default_roles", []string{}).Optional(),
	}
}

func (IdentityProvider) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("identity_providers").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),

		edge.To("federated_identities", FederatedIdentity.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

func (IdentityProvider) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("realm_id", "name").Unique(),
	}
}
