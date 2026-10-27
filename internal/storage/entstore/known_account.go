package entstore

import (
	"context"
	"errors"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/knownaccount"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entKnownAccountRepository struct {
	client *ent.Client
}

func NewKnownAccountRepository(client *ent.Client) repository.KnownAccountRepository {
	return &entKnownAccountRepository{client: client}
}

func (r *entKnownAccountRepository) Touch(ctx context.Context, realmID, deviceHash, userID string, at time.Time) (*domain.KnownAccount, error) {
	// Update first: the common case is an account that signs in again on
	// its device. Two first sign-ins at the same time both try to create:
	// the unique index refuses one, which then updates the other's row.
	for attempt := 0; attempt < 2; attempt++ {
		n, err := r.client.KnownAccount.Update().
			Where(knownaccount.RealmID(realmID), knownaccount.DeviceHash(deviceHash), knownaccount.UserID(userID)).
			SetLastUsedAt(at).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			e, err := r.client.KnownAccount.Query().
				Where(knownaccount.DeviceHash(deviceHash), knownaccount.UserID(userID)).
				Only(ctx)
			if err != nil {
				return nil, mapNotFound(err)
			}
			return toDomainKnownAccount(e), nil
		}
		e, err := r.client.KnownAccount.Create().
			SetRealmID(realmID).
			SetDeviceHash(deviceHash).
			SetUserID(userID).
			SetCreatedAt(at).
			SetLastUsedAt(at).
			Save(ctx)
		if err == nil {
			return toDomainKnownAccount(e), nil
		}
		if !ent.IsConstraintError(err) {
			return nil, err
		}
	}
	return nil, repository.ErrConflict
}

func (r *entKnownAccountRepository) ListByDevice(ctx context.Context, realmID, deviceHash string) ([]*domain.KnownAccount, error) {
	rows, err := r.client.KnownAccount.Query().
		Where(knownaccount.RealmID(realmID), knownaccount.DeviceHash(deviceHash)).
		Order(ent.Desc(knownaccount.FieldLastUsedAt), ent.Asc(knownaccount.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.KnownAccount, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainKnownAccount(e))
	}
	return out, nil
}

func (r *entKnownAccountRepository) GetByID(ctx context.Context, id string) (*domain.KnownAccount, error) {
	e, err := r.client.KnownAccount.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainKnownAccount(e), nil
}

func (r *entKnownAccountRepository) Delete(ctx context.Context, id string) error {
	err := r.client.KnownAccount.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return mapNotFound(err)
	}
	return nil
}

func (r *entKnownAccountRepository) Trim(ctx context.Context, realmID, deviceHash string, keep int) (int, error) {
	if keep < 0 {
		return 0, errors.New("known accounts: keep must not be negative")
	}
	extra, err := r.client.KnownAccount.Query().
		Where(knownaccount.RealmID(realmID), knownaccount.DeviceHash(deviceHash)).
		Order(ent.Desc(knownaccount.FieldLastUsedAt), ent.Asc(knownaccount.FieldID)).
		Offset(keep).
		IDs(ctx)
	if err != nil || len(extra) == 0 {
		return 0, err
	}
	return r.client.KnownAccount.Delete().Where(knownaccount.IDIn(extra...)).Exec(ctx)
}

func toDomainKnownAccount(e *ent.KnownAccount) *domain.KnownAccount {
	return &domain.KnownAccount{
		ID:         e.ID,
		RealmID:    e.RealmID,
		UserID:     e.UserID,
		DeviceHash: e.DeviceHash,
		CreatedAt:  e.CreatedAt,
		LastUsedAt: e.LastUsedAt,
	}
}
