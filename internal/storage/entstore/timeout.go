package entstore

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/predicate"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/timeout"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entTimeoutRepository struct {
	client *ent.Client
}

func NewTimeoutRepository(client *ent.Client) repository.TimeoutRepository {
	return &entTimeoutRepository{client: client}
}

func (r *entTimeoutRepository) Create(ctx context.Context, p repository.CreateTimeoutParams) (*domain.Timeout, error) {
	builder := r.client.Timeout.
		Create().
		SetRealmID(p.RealmID).
		SetTargetType(entschema.TimeoutTargetType(p.TargetType)).
		SetTargetID(p.TargetID).
		SetStartsAt(p.StartsAt).
		SetReason(p.Reason).
		SetCreatedBy(p.CreatedBy)
	if !p.EndsAt.IsZero() {
		builder = builder.SetEndsAt(p.EndsAt)
	}
	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainTimeout(e), nil
}

func (r *entTimeoutRepository) GetByID(ctx context.Context, id string) (*domain.Timeout, error) {
	e, err := r.client.Timeout.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainTimeout(e), nil
}

func (r *entTimeoutRepository) ListByRealm(ctx context.Context, realmID string, f repository.TimeoutFilter, page repository.Page) ([]*domain.Timeout, int, error) {
	where := []predicate.Timeout{timeout.RealmID(realmID)}
	if f.Current != nil {
		// Current: not lifted and not past its end (scheduled or active).
		current := timeout.And(timeout.LiftedAtIsNil(), timeout.Or(timeout.EndsAtIsNil(), timeout.EndsAtGT(f.At)))
		if *f.Current {
			where = append(where, current)
		} else {
			where = append(where, timeout.Not(current))
		}
	}
	q := r.client.Timeout.Query().Where(where...)
	total := -1
	if !page.NoTotal {
		n, err := q.Clone().Count(ctx)
		if err != nil {
			return nil, 0, err
		}
		total = n
	}
	q = q.Order(ent.Desc(timeout.FieldStartsAt), ent.Desc(timeout.FieldCreatedAt))
	if page.Limit > 0 {
		q = q.Limit(page.Limit).Offset(page.Offset)
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, 0, err
	}
	return toDomainTimeouts(rows), total, nil
}

// InForce is a single SELECT:
//
//	WHERE ((target_type = 'user'   AND target_id = $user)
//	    OR (target_type = 'group'  AND target_id IN (SELECT group_id FROM user_groups WHERE user_id = $user))
//	    OR (target_type = 'client' AND target_id = $client))
//	  AND lifted_at IS NULL AND starts_at <= $at AND (ends_at IS NULL OR ends_at > $at)
//
// The user's groups are resolved inside the query: a member added to a
// suspended group is blocked at once, with no cache to clear.
func (r *entTimeoutRepository) InForce(ctx context.Context, userID, clientRef string, at time.Time) ([]*domain.Timeout, error) {
	var targets []predicate.Timeout
	if userID != "" {
		targets = append(targets,
			timeout.And(timeout.TargetType(entschema.TimeoutTargetUser), timeout.TargetID(userID)),
			timeout.And(timeout.TargetType(entschema.TimeoutTargetGroup), targetIsGroupOf(userID)),
		)
	}
	if clientRef != "" {
		targets = append(targets,
			timeout.And(timeout.TargetType(entschema.TimeoutTargetClientApp), timeout.TargetID(clientRef)))
	}
	if len(targets) == 0 {
		return nil, nil
	}
	rows, err := r.client.Timeout.Query().
		Where(timeout.Or(targets...), inForceAt(at)).
		Order(ent.Asc(timeout.FieldStartsAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainTimeouts(rows), nil
}

// targetIsGroupOf: target_id IN (SELECT group_id FROM user_groups WHERE user_id = $1).
func targetIsGroupOf(userID string) predicate.Timeout {
	return predicate.Timeout(func(s *sql.Selector) {
		t := sql.Table(user.GroupsTable)
		s.Where(sql.In(s.C(timeout.FieldTargetID),
			sql.Select(t.C(user.GroupsPrimaryKey[1])).From(t).Where(sql.EQ(t.C(user.GroupsPrimaryKey[0]), userID))))
	})
}

func inForceAt(at time.Time) predicate.Timeout {
	return timeout.And(
		timeout.LiftedAtIsNil(),
		timeout.StartsAtLTE(at),
		timeout.Or(timeout.EndsAtIsNil(), timeout.EndsAtGT(at)),
	)
}

func (r *entTimeoutRepository) Update(ctx context.Context, id string, p repository.UpdateTimeoutParams) (*domain.Timeout, error) {
	builder := r.client.Timeout.Update().Where(timeout.ID(id), timeout.LiftedAtIsNil())
	if p.Reason != nil {
		builder = builder.SetReason(*p.Reason)
	}
	if p.EndsAt != nil {
		if p.EndsAt.IsZero() {
			builder = builder.ClearEndsAt()
		} else {
			builder = builder.SetEndsAt(*p.EndsAt)
		}
	}
	n, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, repository.ErrNotFound
	}
	return r.GetByID(ctx, id)
}

// Lift is one conditional UPDATE: of two administrators lifting the same
// timeout at once, exactly one gets true.
func (r *entTimeoutRepository) Lift(ctx context.Context, id, by string, at time.Time) (bool, error) {
	n, err := r.client.Timeout.Update().
		Where(timeout.ID(id), timeout.LiftedAtIsNil(), timeout.Or(timeout.EndsAtIsNil(), timeout.EndsAtGT(at))).
		SetEndsAt(at).
		SetLiftedAt(at).
		SetLiftedBy(by).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *entTimeoutRepository) ListToEnforce(ctx context.Context, at time.Time, limit int) ([]*domain.Timeout, error) {
	rows, err := r.client.Timeout.Query().
		Where(timeout.EnforcedAtIsNil(), inForceAt(at)).
		Order(ent.Asc(timeout.FieldStartsAt)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainTimeouts(rows), nil
}

// MarkEnforced is conditional too: when two servers run the enforcer, only
// one of them signs the targets out.
func (r *entTimeoutRepository) MarkEnforced(ctx context.Context, id string, at time.Time) (bool, error) {
	n, err := r.client.Timeout.Update().
		Where(timeout.ID(id), timeout.EnforcedAtIsNil()).
		SetEnforcedAt(at).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *entTimeoutRepository) ClearEnforced(ctx context.Context, id string) error {
	return mapNotFound(r.client.Timeout.UpdateOneID(id).ClearEnforcedAt().Exec(ctx))
}

func toDomainTimeouts(rows []*ent.Timeout) []*domain.Timeout {
	out := make([]*domain.Timeout, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainTimeout(e))
	}
	return out
}

func toDomainTimeout(e *ent.Timeout) *domain.Timeout {
	return &domain.Timeout{
		ID:         e.ID,
		RealmID:    e.RealmID,
		TargetType: domain.TimeoutTargetType(e.TargetType),
		TargetID:   e.TargetID,
		StartsAt:   e.StartsAt,
		EndsAt:     e.EndsAt,
		Reason:     e.Reason,
		CreatedBy:  e.CreatedBy,
		CreatedAt:  e.CreatedAt,
		LiftedAt:   e.LiftedAt,
		LiftedBy:   e.LiftedBy,
		EnforcedAt: e.EnforcedAt,
	}
}
