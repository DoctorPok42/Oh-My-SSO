package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/bulkjob"
	"sso.internal/sso/ent/predicate"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entBulkJobRepository struct {
	client *ent.Client
}

func NewBulkJobRepository(client *ent.Client) repository.BulkJobRepository {
	return &entBulkJobRepository{client: client}
}

func (r *entBulkJobRepository) Create(ctx context.Context, p repository.CreateBulkJobParams) (*domain.BulkJob, error) {
	e, err := r.client.BulkJob.Create().
		SetRealmID(p.RealmID).
		SetAction(p.Action).
		SetOperationID(p.OperationID).
		SetRequestedBy(p.RequestedBy).
		SetRequestedByName(p.RequestedByName).
		SetRequestedByRealm(p.RequestedByRealm).
		SetIds(p.IDs).
		SetTotal(len(p.IDs)).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, repository.ErrConflict
		}
		return nil, err
	}
	return toDomainBulkJob(e), nil
}

func (r *entBulkJobRepository) GetByID(ctx context.Context, id string) (*domain.BulkJob, error) {
	e, err := r.client.BulkJob.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainBulkJob(e), nil
}

func (r *entBulkJobRepository) UpdateProgress(ctx context.Context, id string, p repository.BulkJobProgress) error {
	u := r.client.BulkJob.Update().
		Where(bulkjob.ID(id), bulkjob.StatusEQ(entschema.BulkJobRunning)).
		SetProcessed(p.Processed).
		SetDoneCount(p.Done).
		SetSkippedCount(p.Skipped).
		SetFailedCount(p.Failed)
	if p.Items != nil {
		u.SetItems(toEntBulkItems(p.Items))
	}
	return u.Exec(ctx)
}

func (r *entBulkJobRepository) Finish(ctx context.Context, id string, status domain.BulkJobStatus, p repository.BulkJobProgress, at time.Time) (bool, error) {
	n, err := r.client.BulkJob.Update().
		Where(bulkjob.ID(id), bulkjob.StatusEQ(entschema.BulkJobRunning)).
		SetStatus(entschema.BulkJobStatus(status)).
		SetProcessed(p.Processed).
		SetDoneCount(p.Done).
		SetSkippedCount(p.Skipped).
		SetFailedCount(p.Failed).
		SetItems(toEntBulkItems(p.Items)).
		SetFinishedAt(at).
		Save(ctx)
	return n > 0, err
}

func (r *entBulkJobRepository) ReapStale(ctx context.Context, before, at time.Time) ([]*domain.BulkJob, error) {
	stale := []predicate.BulkJob{
		bulkjob.StatusEQ(entschema.BulkJobRunning),
		bulkjob.UpdatedAtLT(before),
	}
	rows, err := r.client.BulkJob.Query().Where(stale...).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*domain.BulkJob
	for _, e := range rows {
		// The condition again: only one process wins each bulk action.
		n, err := r.client.BulkJob.Update().
			Where(bulkjob.ID(e.ID)).
			Where(stale...).
			SetStatus(entschema.BulkJobInterrupted).
			SetFinishedAt(at).
			Save(ctx)
		if err != nil {
			return out, err
		}
		if n > 0 {
			job := toDomainBulkJob(e)
			job.Status, job.FinishedAt = domain.BulkJobInterrupted, &at
			out = append(out, job)
		}
	}
	return out, nil
}

func (r *entBulkJobRepository) SaveItems(ctx context.Context, id string, items []domain.BulkItem) error {
	return r.client.BulkJob.Update().
		Where(bulkjob.ID(id), bulkjob.StatusNEQ(entschema.BulkJobRunning)).
		SetItems(toEntBulkItems(items)).
		Exec(ctx)
}

func (r *entBulkJobRepository) DeleteFinishedBefore(ctx context.Context, before time.Time) (int, error) {
	return r.client.BulkJob.Delete().
		Where(bulkjob.StatusNEQ(entschema.BulkJobRunning), bulkjob.UpdatedAtLT(before)).
		Exec(ctx)
}

func toEntBulkItems(items []domain.BulkItem) []entschema.BulkJobItem {
	out := make([]entschema.BulkJobItem, 0, len(items))
	for _, x := range items {
		out = append(out, entschema.BulkJobItem{ID: x.ID, Label: x.Label, Status: x.Status, Code: x.Code, Message: x.Message})
	}
	return out
}

func toDomainBulkJob(e *ent.BulkJob) *domain.BulkJob {
	items := make([]domain.BulkItem, 0, len(e.Items))
	for _, x := range e.Items {
		items = append(items, domain.BulkItem{ID: x.ID, Label: x.Label, Status: x.Status, Code: x.Code, Message: x.Message})
	}
	return &domain.BulkJob{
		ID: e.ID, RealmID: e.RealmID, Action: e.Action, OperationID: e.OperationID, Status: domain.BulkJobStatus(e.Status),
		RequestedBy: e.RequestedBy, RequestedByName: e.RequestedByName, RequestedByRealm: e.RequestedByRealm,
		IDs: e.Ids, Total: e.Total, Processed: e.Processed,
		Done: e.DoneCount, Skipped: e.SkippedCount, Failed: e.FailedCount,
		Items: items, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, FinishedAt: e.FinishedAt,
	}
}
