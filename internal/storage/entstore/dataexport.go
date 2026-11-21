package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/dataexport"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entDataExportRepository struct {
	client *ent.Client
}

func NewDataExportRepository(client *ent.Client) repository.DataExportRepository {
	return &entDataExportRepository{client: client}
}

func (r *entDataExportRepository) Start(ctx context.Context, e *domain.DataExport, staleBefore time.Time) error {
	// A running export still in time is kept: the insert below then hits
	// the unique index on user_id, also when two requests race.
	if _, err := r.client.DataExport.Delete().Where(
		dataexport.UserID(e.UserID),
		dataexport.Not(dataexport.And(
			dataexport.StatusEQ(entschema.DataExportRunning),
			dataexport.CreatedAtGTE(staleBefore),
		)),
	).Exec(ctx); err != nil {
		return err
	}
	row, err := r.client.DataExport.Create().
		SetRealmID(e.RealmID).
		SetUserID(e.UserID).
		SetStatus(entschema.DataExportRunning).
		SetCreatedAt(e.CreatedAt).
		SetExpiresAt(e.ExpiresAt).
		Save(ctx)
	if ent.IsConstraintError(err) {
		return repository.ErrConflict
	}
	if err != nil {
		return err
	}
	e.ID, e.Status = row.ID, domain.DataExportRunning
	return nil
}

func (r *entDataExportRepository) Finish(ctx context.Context, id string, status domain.DataExportStatus, data []byte, at, expiresAt time.Time) error {
	return r.client.DataExport.Update().
		Where(dataexport.ID(id), dataexport.StatusEQ(entschema.DataExportRunning)).
		SetStatus(entschema.DataExportStatus(status)).
		SetData(data).
		SetFinishedAt(at).
		SetExpiresAt(expiresAt).
		Exec(ctx)
}

func (r *entDataExportRepository) GetByUser(ctx context.Context, userID string) (*domain.DataExport, error) {
	e, err := r.client.DataExport.Query().Where(dataexport.UserID(userID)).
		Select(dataexport.FieldID, dataexport.FieldRealmID, dataexport.FieldUserID, dataexport.FieldStatus,
			dataexport.FieldCreatedAt, dataexport.FieldFinishedAt, dataexport.FieldExpiresAt).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &domain.DataExport{
		ID: e.ID, RealmID: e.RealmID, UserID: e.UserID, Status: domain.DataExportStatus(e.Status),
		CreatedAt: e.CreatedAt, FinishedAt: e.FinishedAt, ExpiresAt: e.ExpiresAt,
	}, nil
}

func (r *entDataExportRepository) GetData(ctx context.Context, id string) ([]byte, error) {
	e, err := r.client.DataExport.Query().Where(dataexport.ID(id)).Select(dataexport.FieldData).Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return e.Data, nil
}
