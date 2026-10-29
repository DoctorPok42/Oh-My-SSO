package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/trusteddevice"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entTrustedDeviceRepository struct {
	client *ent.Client
}

func NewTrustedDeviceRepository(client *ent.Client) repository.TrustedDeviceRepository {
	return &entTrustedDeviceRepository{client: client}
}

// Put trusts a device: it updates the row of (user, device), or creates it.
// Two sign-ins ticking the box at the same time both try to create: the
// unique index refuses one, which then updates the other's row.
func (r *entTrustedDeviceRepository) Put(ctx context.Context, p repository.PutTrustedDeviceParams) (*domain.TrustedDevice, error) {
	for attempt := 0; attempt < 3; attempt++ {
		n, err := r.client.TrustedDevice.Update().
			Where(trusteddevice.UserID(p.UserID), trusteddevice.DeviceHash(p.DeviceHash)).
			SetCreatedAt(p.CreatedAt).
			SetExpiresAt(p.ExpiresAt).
			ClearLastUsedAt().
			SetNillableIPAddress(nonEmpty(p.IPAddress)).
			SetNillableUserAgent(nonEmpty(p.UserAgent)).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			return r.Get(ctx, p.UserID, p.DeviceHash)
		}
		e, err := r.client.TrustedDevice.Create().
			SetRealmID(p.RealmID).
			SetUserID(p.UserID).
			SetDeviceHash(p.DeviceHash).
			SetNillableIPAddress(nonEmpty(p.IPAddress)).
			SetNillableUserAgent(nonEmpty(p.UserAgent)).
			SetCreatedAt(p.CreatedAt).
			SetExpiresAt(p.ExpiresAt).
			Save(ctx)
		if err == nil {
			return toDomainTrustedDevice(e), nil
		}
		if !ent.IsConstraintError(err) {
			return nil, err
		}
	}
	return nil, repository.ErrConflict
}

func (r *entTrustedDeviceRepository) Get(ctx context.Context, userID, deviceHash string) (*domain.TrustedDevice, error) {
	e, err := r.client.TrustedDevice.Query().
		Where(trusteddevice.UserID(userID), trusteddevice.DeviceHash(deviceHash)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainTrustedDevice(e), nil
}

func (r *entTrustedDeviceRepository) MarkUsed(ctx context.Context, id string, at time.Time, ip, userAgent string) error {
	err := r.client.TrustedDevice.UpdateOneID(id).
		SetLastUsedAt(at).
		SetNillableIPAddress(nonEmpty(ip)).
		SetNillableUserAgent(nonEmpty(userAgent)).
		Exec(ctx)
	return mapNotFound(err)
}

func (r *entTrustedDeviceRepository) ListByUser(ctx context.Context, userID string, now time.Time) ([]*domain.TrustedDevice, error) {
	rows, err := r.client.TrustedDevice.Query().
		Where(trusteddevice.UserID(userID), trusteddevice.ExpiresAtGT(now)).
		Order(ent.Desc(trusteddevice.FieldCreatedAt), ent.Asc(trusteddevice.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.TrustedDevice, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainTrustedDevice(e))
	}
	return out, nil
}

func (r *entTrustedDeviceRepository) Delete(ctx context.Context, id string) error {
	return mapNotFound(r.client.TrustedDevice.DeleteOneID(id).Exec(ctx))
}

func (r *entTrustedDeviceRepository) DeleteByUser(ctx context.Context, userID string) (int, error) {
	return r.client.TrustedDevice.Delete().Where(trusteddevice.UserID(userID)).Exec(ctx)
}

func (r *entTrustedDeviceRepository) DeleteByDevice(ctx context.Context, userID, deviceHash string) (int, error) {
	return r.client.TrustedDevice.Delete().
		Where(trusteddevice.UserID(userID), trusteddevice.DeviceHash(deviceHash)).
		Exec(ctx)
}

func (r *entTrustedDeviceRepository) DeleteExpired(ctx context.Context, userID string, now time.Time) (int, error) {
	return r.client.TrustedDevice.Delete().
		Where(trusteddevice.UserID(userID), trusteddevice.ExpiresAtLTE(now)).
		Exec(ctx)
}

func toDomainTrustedDevice(e *ent.TrustedDevice) *domain.TrustedDevice {
	d := &domain.TrustedDevice{
		ID:         e.ID,
		RealmID:    e.RealmID,
		UserID:     e.UserID,
		DeviceHash: e.DeviceHash,
		IPAddress:  e.IPAddress,
		UserAgent:  e.UserAgent,
		CreatedAt:  e.CreatedAt,
		ExpiresAt:  e.ExpiresAt,
	}
	if e.LastUsedAt != nil {
		d.LastUsedAt = *e.LastUsedAt
	}
	return d
}
