package entstore

import (
	"context"
	"fmt"
	"reflect"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

var auditedTypes = map[string]bool{
	"ClientApp":  true,
	"Role":       true,
	"SigningKey": true,
	"MfaMethod":  true,
	"Session":    true,
	"Consent":    true,
	"User":       true,
}

type mutationID interface {
	ID() (string, bool)
}

func AuditLogHook(client *ent.Client) ent.Hook {
	auditRepo := NewAuditLogRepository(client)
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			v, err := next.Mutate(ctx, m)
			if err != nil || !auditedTypes[m.Type()] {
				return v, err
			}

			actor, _ := audit.ActorFromContext(ctx)
			action := auditAction(m.Op())
			_, auditErr := auditRepo.Create(ctx, repository.CreateAuditLogParams{
				RealmID:      resolveRealmID(m, actor),
				UserID:       actor.UserID,
				Action:       action,
				ResourceType: m.Type(),
				ResourceID:   resourceID(m, v),
				Level:        domain.AuditLogInfo,
				Status:       domain.AuditLogSuccess,
			})
			if auditErr != nil {
				return v, fmt.Errorf("mutation %s sur %s réussie mais écriture AuditLog échouée: %w", action, m.Type(), auditErr)
			}
			return v, nil
		})
	}
}

func resolveRealmID(m ent.Mutation, actor audit.Actor) string {
	if actor.RealmID != "" {
		return actor.RealmID
	}
	if v, ok := m.Field("realm_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func resourceID(m ent.Mutation, v ent.Value) string {
	if withID, ok := m.(mutationID); ok {
		if id, exists := withID.ID(); exists {
			return id
		}
	}
	return idFromValue(v)
}

func idFromValue(v ent.Value) string {
	if v == nil {
		return ""
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return ""
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return ""
	}
	f := rv.FieldByName("ID")
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return f.String()
}

func auditAction(op ent.Op) string {
	switch {
	case op.Is(ent.OpCreate):
		return "create"
	case op.Is(ent.OpUpdateOne), op.Is(ent.OpUpdate):
		return "update"
	case op.Is(ent.OpDeleteOne), op.Is(ent.OpDelete):
		return "delete"
	default:
		return "unknown"
	}
}
