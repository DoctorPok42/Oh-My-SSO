package entstore

import (
	"context"
	"slices"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/predicate"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/userimportjob"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entUserImportRepository struct {
	client *ent.Client
}

func NewUserImportRepository(client *ent.Client) repository.UserImportRepository {
	return &entUserImportRepository{client: client}
}

func (r *entUserImportRepository) Create(ctx context.Context, p repository.CreateUserImportParams) (*domain.UserImportJob, error) {
	e, err := r.client.UserImportJob.Create().
		SetRealmID(p.RealmID).
		SetFileName(p.FileName).
		SetRequestedBy(p.RequestedBy).
		SetRequestedByName(p.RequestedByName).
		SetRequestedByRealm(p.RequestedByRealm).
		SetSendEmail(p.SendEmail).
		SetNotifyWhenDone(p.NotifyWhenDone).
		SetTotal(p.Total).
		SetIgnoredColumns(p.IgnoredColumns).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, repository.ErrConflict
		}
		return nil, err
	}
	return toDomainUserImport(e), nil
}

func (r *entUserImportRepository) GetByID(ctx context.Context, id string) (*domain.UserImportJob, error) {
	e, err := r.client.UserImportJob.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainUserImport(e), nil
}

func (r *entUserImportRepository) ListByRealm(ctx context.Context, realmID string, limit int) ([]*domain.UserImportJob, error) {
	// Every column but rows: a report can be large, and this list only
	// shows its totals.
	columns := slices.DeleteFunc(slices.Clone(userimportjob.Columns), func(c string) bool {
		return c == userimportjob.FieldRows
	})
	rows, err := r.client.UserImportJob.Query().
		Where(userimportjob.RealmID(realmID)).
		Order(ent.Desc(userimportjob.FieldCreatedAt)).
		Limit(limit).
		Select(columns...).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.UserImportJob, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainUserImport(e))
	}
	return out, nil
}

func (r *entUserImportRepository) UpdateProgress(ctx context.Context, id string, p repository.UserImportProgress) error {
	u := r.client.UserImportJob.Update().
		Where(userimportjob.ID(id), userimportjob.StatusEQ(entschema.UserImportRunning)).
		SetProcessed(p.Processed).
		SetCreatedCount(p.Created).
		SetFailedCount(p.Failed)
	if p.Rows != nil {
		u.SetRows(toEntUserImportRows(p.Rows))
	}
	return u.Exec(ctx)
}

func (r *entUserImportRepository) Finish(ctx context.Context, id string, status domain.UserImportStatus, p repository.UserImportProgress, at time.Time) (bool, error) {
	n, err := r.client.UserImportJob.Update().
		Where(userimportjob.ID(id), userimportjob.StatusEQ(entschema.UserImportRunning)).
		SetStatus(entschema.UserImportStatus(status)).
		SetProcessed(p.Processed).
		SetCreatedCount(p.Created).
		SetFailedCount(p.Failed).
		SetRows(toEntUserImportRows(p.Rows)).
		SetFinishedAt(at).
		Save(ctx)
	return n > 0, err
}

func (r *entUserImportRepository) ReapStale(ctx context.Context, before, at time.Time) ([]*domain.UserImportJob, error) {
	stale := []predicate.UserImportJob{
		userimportjob.StatusEQ(entschema.UserImportRunning),
		userimportjob.UpdatedAtLT(before),
	}
	rows, err := r.client.UserImportJob.Query().Where(stale...).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*domain.UserImportJob
	for _, e := range rows {
		// The condition again: only one process wins each import.
		n, err := r.client.UserImportJob.Update().
			Where(userimportjob.ID(e.ID)).
			Where(stale...).
			SetStatus(entschema.UserImportInterrupted).
			SetFinishedAt(at).
			Save(ctx)
		if err != nil {
			return out, err
		}
		if n > 0 {
			job := toDomainUserImport(e)
			job.Status, job.FinishedAt = domain.UserImportInterrupted, &at
			out = append(out, job)
		}
	}
	return out, nil
}

func (r *entUserImportRepository) DeleteFinishedBefore(ctx context.Context, before time.Time) (int, error) {
	return r.client.UserImportJob.Delete().
		Where(userimportjob.StatusNEQ(entschema.UserImportRunning), userimportjob.UpdatedAtLT(before)).
		Exec(ctx)
}

func toEntUserImportRows(rows []domain.UserImportRow) []entschema.UserImportRow {
	out := make([]entschema.UserImportRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, entschema.UserImportRow{
			Line: x.Line, Email: x.Email, Username: x.Username, Status: x.Status,
			Error: x.Error, UserID: x.UserID, Emailed: x.Emailed, Groups: x.Groups, Roles: x.Roles,
		})
	}
	return out
}

func toDomainUserImport(e *ent.UserImportJob) *domain.UserImportJob {
	rows := make([]domain.UserImportRow, 0, len(e.Rows))
	for _, x := range e.Rows {
		rows = append(rows, domain.UserImportRow{
			Line: x.Line, Email: x.Email, Username: x.Username, Status: x.Status,
			Error: x.Error, UserID: x.UserID, Emailed: x.Emailed, Groups: x.Groups, Roles: x.Roles,
		})
	}
	return &domain.UserImportJob{
		ID: e.ID, RealmID: e.RealmID, Status: domain.UserImportStatus(e.Status), FileName: e.FileName,
		RequestedBy: e.RequestedBy, RequestedByName: e.RequestedByName, RequestedByRealm: e.RequestedByRealm,
		SendEmail: e.SendEmail, NotifyWhenDone: e.NotifyWhenDone,
		Total: e.Total, Processed: e.Processed, Created: e.CreatedCount, Failed: e.FailedCount,
		IgnoredColumns: e.IgnoredColumns, Rows: rows,
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, FinishedAt: e.FinishedAt,
	}
}
