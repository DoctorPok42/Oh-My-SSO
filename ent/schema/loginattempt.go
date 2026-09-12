package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

type LoginAttempt struct {
	ent.Schema
}

type LoginAttemptStatus string

const (
	LoginAttemptSuccess LoginAttemptStatus = "success"
	LoginAttemptFailure LoginAttemptStatus = "failure"
)

type LoginAttemptFailureReason string

const (
	LoginFailureInvalidCredentials LoginAttemptFailureReason = "invalid_credentials"
	LoginFailureAccountLocked      LoginAttemptFailureReason = "account_locked"
	LoginFailureMfaFailed          LoginAttemptFailureReason = "mfa_failed"
	LoginFailureUnknownAccount     LoginAttemptFailureReason = "unknown_account"
	LoginFailureTimeoutActive      LoginAttemptFailureReason = "timeout_active"
	LoginFailureAccessDenied       LoginAttemptFailureReason = "access_denied"
)

func (LoginAttempt) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("identifier").NotEmpty().Immutable(),
		field.String("ip_address").Optional().Immutable(),
		field.String("user_agent").Optional().Immutable(),
		field.String("status").GoType(LoginAttemptStatus("")).Immutable(),
		field.String("failure_reason").Optional().Immutable(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
	}
}

func (LoginAttempt) Edges() []ent.Edge {
	return nil
}

func (LoginAttempt) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("identifier", "created_at"),
		index.Fields("ip_address", "created_at"),
	}
}
