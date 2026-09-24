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

var activeStatus = entschema.SessionStatus(domain.SessionActive)

func (r *entSessionRepository) Create(ctx context.Context, p repository.CreateSessionParams) (*domain.Session, error) {
	e, err := r.client.Session.
		Create().
		SetTokenHash(p.TokenHash).
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
		return nil, mapNotFound(err)
	}
	return toDomainSession(e), nil
}

func (r *entSessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	e, err := r.client.Session.
		Query().
		Where(session.TokenHash(tokenHash)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainSession(e), nil
}

func (r *entSessionRepository) ListActiveByUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	rows, err := r.client.Session.
		Query().
		Where(
			session.UserID(userID),
			session.Status(activeStatus),
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

func (r *entSessionRepository) Touch(ctx context.Context, id string, at time.Time) error {
	_, err := r.client.Session.
		UpdateOneID(id).
		SetLastActivityAt(at).
		Save(ctx)
	return mapNotFound(err)
}

func (r *entSessionRepository) MarkExpired(ctx context.Context, id string) error {
	n, err := r.client.Session.
		Update().
		Where(session.ID(id), session.Status(activeStatus)).
		SetStatus(entschema.SessionStatus(domain.SessionExpired)).
		SetRevokedReason(string(domain.SessionRevokedExpired)).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *entSessionRepository) Revoke(ctx context.Context, id string, reason domain.SessionRevokedReason) error {
	n, err := r.client.Session.
		Update().
		Where(session.ID(id), session.Status(activeStatus)).
		SetStatus(entschema.SessionStatus(domain.SessionRevoked)).
		SetRevokedReason(string(reason)).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *entSessionRepository) RevokeAllByUser(ctx context.Context, userID string, reason domain.SessionRevokedReason) ([]*domain.Session, error) {
	active, err := r.ListActiveByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(active) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(active))
	for _, s := range active {
		ids = append(ids, s.ID)
	}

	_, err = r.client.Session.
		Update().
		Where(session.IDIn(ids...), session.Status(activeStatus)).
		SetStatus(entschema.SessionStatus(domain.SessionRevoked)).
		SetRevokedReason(string(reason)).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return active, nil
}

func (r *entSessionRepository) Delete(ctx context.Context, id string) error {
	return mapNotFound(r.client.Session.DeleteOneID(id).Exec(ctx))
}

func toDomainSession(e *ent.Session) *domain.Session {
	return &domain.Session{
		ID:                e.ID,
		TokenHash:         e.TokenHash,
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
