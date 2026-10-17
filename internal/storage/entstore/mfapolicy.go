package entstore

import (
	"context"
	"fmt"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/mfapolicy"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entMfaPolicyRepository struct {
	client *ent.Client
}

func NewMfaPolicyRepository(client *ent.Client) repository.MfaPolicyRepository {
	return &entMfaPolicyRepository{client: client}
}

func (r *entMfaPolicyRepository) Upsert(ctx context.Context, p repository.UpsertMfaPolicyParams) (*domain.MfaPolicy, error) {
	managedBy := p.ManagedBy
	if managedBy == "" {
		managedBy = domain.MfaPolicyManagedByUI
	}
	methods := methodsToStrings(p.AllowedMethods)

	existing, err := r.client.MfaPolicy.Query().Where(mfapolicy.RoleID(p.RoleID)).Only(ctx)
	switch {
	case ent.IsNotFound(err):
		e, err := r.client.MfaPolicy.Create().
			SetRealmID(p.RealmID).
			SetRoleID(p.RoleID).
			SetManagedBy(entschema.MfaPolicyManagedBy(managedBy)).
			SetRequired(p.Required).
			SetAllowedMethods(methods).
			SetEnrollmentGraceDays(p.EnrollmentGraceDays).
			SetStepUpForSensitiveActions(p.StepUpForSensitiveActions).
			SetNillableRequiredSince(nonZeroTime(p.RequiredSince)).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("create mfa policy: %w", err)
		}
		return toDomainMfaPolicy(e), nil
	case err != nil:
		return nil, err
	}

	upd := r.client.MfaPolicy.UpdateOneID(existing.ID).
		SetManagedBy(entschema.MfaPolicyManagedBy(managedBy)).
		SetRequired(p.Required).
		SetAllowedMethods(methods).
		SetEnrollmentGraceDays(p.EnrollmentGraceDays).
		SetStepUpForSensitiveActions(p.StepUpForSensitiveActions)
	if p.RequiredSince.IsZero() {
		upd = upd.ClearRequiredSince()
	} else {
		upd = upd.SetRequiredSince(p.RequiredSince)
	}
	e, err := upd.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("update mfa policy: %w", err)
	}
	return toDomainMfaPolicy(e), nil
}

func (r *entMfaPolicyRepository) GetByRole(ctx context.Context, roleID string) (*domain.MfaPolicy, error) {
	e, err := r.client.MfaPolicy.Query().Where(mfapolicy.RoleID(roleID)).Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainMfaPolicy(e), nil
}

func (r *entMfaPolicyRepository) ListByRealm(ctx context.Context, realmID string) ([]*domain.MfaPolicy, error) {
	rows, err := r.client.MfaPolicy.Query().
		Where(mfapolicy.RealmID(realmID)).
		Order(ent.Asc(mfapolicy.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaPolicies(rows), nil
}

func (r *entMfaPolicyRepository) ListByRoleIDs(ctx context.Context, roleIDs []string) ([]*domain.MfaPolicy, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	rows, err := r.client.MfaPolicy.Query().Where(mfapolicy.RoleIDIn(roleIDs...)).All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainMfaPolicies(rows), nil
}

func (r *entMfaPolicyRepository) DeleteByRole(ctx context.Context, roleID string) error {
	n, err := r.client.MfaPolicy.Delete().Where(mfapolicy.RoleID(roleID)).Exec(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func toDomainMfaPolicies(rows []*ent.MfaPolicy) []*domain.MfaPolicy {
	out := make([]*domain.MfaPolicy, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainMfaPolicy(e))
	}
	return out
}

func toDomainMfaPolicy(e *ent.MfaPolicy) *domain.MfaPolicy {
	return &domain.MfaPolicy{
		ID:                        e.ID,
		RealmID:                   e.RealmID,
		RoleID:                    e.RoleID,
		ManagedBy:                 domain.MfaPolicyManagedBy(e.ManagedBy),
		Required:                  e.Required,
		AllowedMethods:            stringsToMethods(e.AllowedMethods),
		EnrollmentGraceDays:       e.EnrollmentGraceDays,
		StepUpForSensitiveActions: e.StepUpForSensitiveActions,
		RequiredSince:             e.RequiredSince,
		CreatedAt:                 e.CreatedAt,
		UpdatedAt:                 e.UpdatedAt,
	}
}

// methodsToStrings / stringsToMethods convert between the domain type and
// the JSON column ([]string). A nil or empty list means "any method".
func methodsToStrings(in []domain.MfaMethodType) []string {
	out := make([]string, 0, len(in))
	for _, m := range in {
		out = append(out, string(m))
	}
	return out
}

func stringsToMethods(in []string) []domain.MfaMethodType {
	if len(in) == 0 {
		return nil
	}
	out := make([]domain.MfaMethodType, 0, len(in))
	for _, m := range in {
		out = append(out, domain.MfaMethodType(m))
	}
	return out
}
