package entstore

import (
	"context"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/predicate"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entUserRepository struct {
	client *ent.Client
}

func NewUserRepository(client *ent.Client) repository.UserRepository {
	return &entUserRepository{client: client}
}

func (r *entUserRepository) Create(ctx context.Context, p repository.CreateUserParams) (*domain.User, error) {
	builder := r.client.User.
		Create().
		SetRealmID(p.RealmID).
		SetUsername(p.Username).
		SetEmail(p.Email).
		SetPasswordHash(p.PasswordHash)

	if p.Status != "" {
		builder = builder.SetStatus(entschema.UserStatus(p.Status))
	}

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	e, err := r.client.User.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) GetByRealmAndEmail(ctx context.Context, realmID, email string) (*domain.User, error) {
	e, err := r.client.User.
		Query().
		Where(user.RealmID(realmID), user.EmailEQ(email)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) GetByRealmAndUsername(ctx context.Context, realmID, username string) (*domain.User, error) {
	e, err := r.client.User.
		Query().
		Where(user.RealmID(realmID), user.UsernameEQ(username)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) Update(ctx context.Context, id string, p repository.UpdateUserParams) (*domain.User, error) {
	builder := r.client.User.UpdateOneID(id)

	if p.Username != nil {
		builder = builder.SetUsername(*p.Username)
	}
	if p.Email != nil {
		builder = builder.SetEmail(*p.Email)
	}
	if p.PasswordHash != nil {
		builder = builder.SetPasswordHash(*p.PasswordHash)
	}
	if p.Status != nil {
		builder = builder.SetStatus(entschema.UserStatus(*p.Status))
	}

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) Delete(ctx context.Context, id string) error {
	return r.client.User.DeleteOneID(id).Exec(ctx)
}

// CompareAndSwapLockout is a single UPDATE ... WHERE <every lockout column
// still has its old value>. If another request changed the row in between,
// no row matches and the caller reloads and tries again.
func (r *entUserRepository) CompareAndSwapLockout(ctx context.Context, id string, old, next domain.LockoutState) (bool, error) {
	upd := r.client.User.Update().
		Where(
			user.ID(id),
			user.FailedLoginCount(old.FailedCount),
			user.LockoutCount(old.LockCount),
			timeIs(old.LastFailedAt, user.LastFailedLoginAtIsNil, user.LastFailedLoginAtEQ),
			timeIs(old.LockedUntil, user.LockedUntilIsNil, user.LockedUntilEQ),
			timeIs(old.LastLockedAt, user.LastLockedAtIsNil, user.LastLockedAtEQ),
		).
		SetFailedLoginCount(next.FailedCount).
		SetLockoutCount(next.LockCount)

	if next.LastFailedAt.IsZero() {
		upd = upd.ClearLastFailedLoginAt()
	} else {
		upd = upd.SetLastFailedLoginAt(next.LastFailedAt)
	}
	if next.LockedUntil.IsZero() {
		upd = upd.ClearLockedUntil()
	} else {
		upd = upd.SetLockedUntil(next.LockedUntil)
	}
	if next.LastLockedAt.IsZero() {
		upd = upd.ClearLastLockedAt()
	} else {
		upd = upd.SetLastLockedAt(next.LastLockedAt)
	}

	n, err := upd.Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// timeIs matches a nullable time column: IS NULL for a zero time.
func timeIs(t time.Time, isNil func() predicate.User, eq func(time.Time) predicate.User) predicate.User {
	if t.IsZero() {
		return isNil()
	}
	return eq(t)
}

func lockoutFromEnt(e *ent.User) domain.LockoutState {
	return domain.LockoutState{
		FailedCount:  e.FailedLoginCount,
		LastFailedAt: derefTime(e.LastFailedLoginAt),
		LockedUntil:  derefTime(e.LockedUntil),
		LockCount:    e.LockoutCount,
		LastLockedAt: derefTime(e.LastLockedAt),
	}
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func toDomainUser(e *ent.User) *domain.User {
	return &domain.User{
		ID:           e.ID,
		RealmID:      e.RealmID,
		Username:     e.Username,
		Email:        e.Email,
		PasswordHash: e.PasswordHash,
		CreatedAt:    e.CreatedAt,
		UpdatedAt:    e.UpdatedAt,
		DeletedAt:    e.DeletedAt,
		Status:       domain.UserStatus(e.Status),
		LastLoginAt:  e.LastLoginAt,
		Profile:      e.Profile,
		Lockout:      lockoutFromEnt(e),
	}
}
