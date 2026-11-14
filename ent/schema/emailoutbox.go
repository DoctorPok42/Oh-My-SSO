package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// EmailOutbox is the outbox of the e-mails: one row per e-mail to send
// (notify.Dispatcher). The request that asks for an e-mail writes the row;
// the dispatchers of every server send it, try again later when the mail
// server fails (growing delays, up to 24 h or the end of the link it
// carries), and record the outcome. A restart or an SMTP outage loses
// nothing: the row waits.
//
// The link of a reset, activation or verification e-mail is the one secret:
// it is kept sealed (envelope encryption, like the TOTP secrets), bound to
// the row's id, in "sealed_token". Everything else is in "event".
type EmailOutbox struct {
	ent.Schema
}

type EmailOutboxStatus string

const (
	EmailOutboxPending EmailOutboxStatus = "pending" // waiting for its next attempt
	EmailOutboxSent    EmailOutboxStatus = "sent"
	// EmailOutboxFailed: the mail server refused it for good, or it could
	// not leave before its deadline.
	EmailOutboxFailed EmailOutboxStatus = "failed"
	// EmailOutboxCancelled: no longer worth sending (its link was used or
	// replaced, the account is gone, the realm switched the alert off).
	EmailOutboxCancelled EmailOutboxStatus = "cancelled"
)

func (EmailOutbox) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Table: "email_outbox"}}
}

func (EmailOutbox) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Immutable().
			DefaultFunc(uuid.NewString),
		field.String("realm_id").NotEmpty().Immutable(),
		// The recipient's account: its current address is read when the
		// e-mail leaves.
		field.String("user_id").NotEmpty().Immutable(),
		field.String("kind").NotEmpty().Immutable(),
		// The notification event, as JSON, without its link.
		field.Text("event").Immutable(),
		field.Text("sealed_token").Optional().Sensitive().Immutable(),
		field.String("status").GoType(EmailOutboxStatus("")).Default(string(EmailOutboxPending)),
		field.Int("attempts").Default(0),
		field.Time("next_attempt_at"),
		// Given up after this: 24 h after it was asked for, sooner when its
		// link expires first.
		field.Time("deadline"),
		// A dispatcher holds the row until then while it sends it; another
		// one takes it over afterwards (the first one died).
		field.Time("locked_until").Optional().Nillable(),
		// claim: the dispatcher's mark when it takes the row (see Claim).
		field.String("claim").Optional(),
		field.String("last_error").Optional(),
		// Where it went, and with which template, once sent or tried.
		field.String("recipient").Optional(),
		field.String("template").Optional(),
		field.Time("created_at").Default(func() time.Time { return time.Now() }).Immutable(),
		field.Time("updated_at").Default(func() time.Time { return time.Now() }).UpdateDefault(func() time.Time { return time.Now() }),
		field.Time("sent_at").Optional().Nillable(),
	}
}

func (EmailOutbox) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("email_outbox").
			Field("user_id").
			Immutable().
			Unique().
			Required(),
	}
}

func (EmailOutbox) Indexes() []ent.Index {
	return []ent.Index{
		// The dispatchers' query: the pending e-mails that are due.
		index.Fields("status", "next_attempt_at"),
		// The e-mails of an account (console), newest first.
		index.Fields("user_id", "created_at"),
		// The purge: the e-mails of a realm that ended.
		index.Fields("realm_id", "updated_at"),
	}
}
