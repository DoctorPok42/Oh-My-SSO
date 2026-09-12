package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type AuditLog struct {
	ent.Schema
}

type AuditLogLevel string

const (
	AuditLogDebug      AuditLogLevel = "debug"
	AuditLogSuspicious AuditLogLevel = "suspicious"
	AuditLogInfo       AuditLogLevel = "info"
	AuditLogWarning    AuditLogLevel = "warning"
	AuditLogError      AuditLogLevel = "error"
	AuditLogCritical   AuditLogLevel = "critical"
)

type AuditLogStatus string

const (
	AuditLogSuccess AuditLogStatus = "success"
	AuditLogFailure AuditLogStatus = "failure"
)

func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		field.String("user_id").Optional(),
		field.String("action").NotEmpty(),
		field.String("resource_type").Optional(),
		field.String("resource_id").Optional(),
		field.Time("timestamp").Default(func() time.Time { return time.Now() }).Immutable(),
		field.String("ip_address").Optional(),
		field.String("user_agent").Optional(),
		field.String("level").GoType(AuditLogLevel("")).Default(string(AuditLogInfo)),
		field.String("status").GoType(AuditLogStatus("")).Default(string(AuditLogSuccess)),
		field.JSON("details", map[string]interface{}{}).Optional(),
	}
}

func (AuditLog) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("realm", Realm.Type).
			Ref("audit_logs").
			Field("realm_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("resource_type", "resource_id"),
		index.Fields("user_id", "timestamp"),
		index.Fields("realm_id", "timestamp"),
	}
}
