package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/session"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entSessionRepository struct {
	client *ent.Client
}

func NewSessionRepository(client *ent.Client) repository.SessionRepository {
	return &entSessionRepository{client: client}
}

func (r *entSessionRepository) Create(ctx context.Context, p repository.CreateSessionParams) (*domain.Session, error) {
	e, err := r.client.Session.
		Create().
		SetRealmID(p.RealmID).
		SetUserID(p.UserID).
		SetExpiresAt(p.ExpiresAt).
		SetNillableIPAddress(nonEmpty(p.IPAddress)).
		SetNillableUserAgent(nonEmpty(p.UserAgent)).
		SetNillableDeviceFingerprint(nonEmpty(p.DeviceFingerprint)).
		SetMfaVerified(p.MFAVerified).
		SetNillableMfaMethodType(nonEmpty(p.MFAMethodType)).
		SetAuthMethod(p.AuthMethod).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainSession(e), nil
}

func (r *entSessionRepository) GetByID(ctx context.Context, id string) (*domain.Session, error) {
	e, err := r.client.Session.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return toDomainSession(e), nil
}

func (r *entSessionRepository) ListActiveByUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	rows, err := r.client.Session.
		Query().
		Where(
			session.UserID(userID),
			session.Status(entschema.SessionStatus(domain.SessionActive)),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Session, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainSession(e))
	}
	return out, nil
}

func (r *entSessionRepository) Touch(ctx context.Context, id string) error {
	_, err := r.client.Session.
		UpdateOneID(id).
		SetLastActivityAt(time.Now()).
		Save(ctx)
	return err
}

func (r *entSessionRepository) Revoke(ctx context.Context, id string, reason domain.SessionRevokedReason) error {
	_, err := r.client.Session.
		UpdateOneID(id).
		SetStatus(entschema.SessionStatus(domain.SessionRevoked)).
		SetRevokedReason(string(reason)).
		Save(ctx)
	return err
}

func (r *entSessionRepository) Delete(ctx context.Context, id string) error {
	return r.client.Session.DeleteOneID(id).Exec(ctx)
}

func toDomainSession(e *ent.Session) *domain.Session {
	return &domain.Session{
		ID:                e.ID,
		RealmID:           e.RealmID,
		UserID:            e.UserID,
		CreatedAt:         e.CreatedAt,
		ExpiresAt:         e.ExpiresAt,
		LastActivityAt:    e.LastActivityAt,
		IPAddress:         e.IPAddress,
		UserAgent:         e.UserAgent,
		DeviceFingerprint: e.DeviceFingerprint,
		MFAVerified:       e.MfaVerified,
		MFAMethodType:     e.MfaMethodType,
		AuthMethod:        e.AuthMethod,
		Status:            domain.SessionStatus(e.Status),
		RevokedReason:     domain.SessionRevokedReason(e.RevokedReason),
	}
}
