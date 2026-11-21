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
		SetUsername(domain.NormalizeIdentifier(p.Username)).
		SetEmail(domain.NormalizeIdentifier(p.Email)).
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
		Where(user.RealmID(realmID), user.EmailEQ(domain.NormalizeIdentifier(email))).
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
		Where(user.RealmID(realmID), user.UsernameEQ(domain.NormalizeIdentifier(username))).
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
	applyUserFields(builder, p)
	verify := p.EmailVerified != nil && *p.EmailVerified
	applyEmailVerified(builder, p, verify)

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	if verify && p.Email == nil && e.EmailVerifiedAt == nil {
		// Only when not verified yet: the date says since when.
		if _, err := r.client.User.Update().
			Where(user.ID(id), user.EmailVerifiedAtIsNil()).
			SetEmailVerifiedAt(time.Now()).
			Save(ctx); err != nil {
			return nil, err
		}
		if e, err = r.client.User.Get(ctx, id); err != nil {
			return nil, mapNotFound(err)
		}
	}
	return toDomainUser(e), nil
}

// applyUserFields sets the fields p carries (the builder mutates in place).
func applyUserFields(b *ent.UserUpdateOne, p repository.UpdateUserParams) {
	if p.Username != nil {
		b.SetUsername(domain.NormalizeIdentifier(*p.Username))
	}
	if p.Email != nil {
		// A new address cancels the change the user was waiting for.
		b.SetEmail(domain.NormalizeIdentifier(*p.Email)).ClearPendingEmail()
	} else if p.PendingEmail != nil {
		b.SetPendingEmail(domain.NormalizeIdentifier(*p.PendingEmail))
	}
	if p.PasswordHash != nil {
		b.SetPasswordHash(*p.PasswordHash)
	}
	if p.PasswordChangedAt != nil {
		b.SetPasswordChangedAt(*p.PasswordChangedAt)
	}
	if p.PasswordHistory != nil {
		b.SetPasswordHistory(*p.PasswordHistory)
	}
	if p.Status != nil {
		b.SetStatus(entschema.UserStatus(*p.Status))
	}
	if p.MustChangePassword != nil {
		b.SetMustChangePassword(*p.MustChangePassword)
	}
}

// applyEmailVerified: a new address is verified from now when p says so, and
// not verified otherwise, whatever the old one was. verify without a new
// address is applied after the save (Update).
func applyEmailVerified(b *ent.UserUpdateOne, p repository.UpdateUserParams, verify bool) {
	switch {
	case verify && p.Email != nil:
		b.SetEmailVerifiedAt(time.Now())
	case !verify && (p.EmailVerified != nil || p.Email != nil):
		b.ClearEmailVerifiedAt()
	}
}

func (r *entUserRepository) Delete(ctx context.Context, id string) error {
	return mapNotFound(r.client.User.DeleteOneID(id).Exec(ctx))
}

// CompareAndSwapPasswordHash is a single UPDATE ... SET password_hash = next
// WHERE id = ... AND password_hash = old: if the password changed since the
// caller read it (a password reset), no row matches and nothing is written.
func (r *entUserRepository) CompareAndSwapPasswordHash(ctx context.Context, id, old, next string) (bool, error) {
	n, err := r.client.User.Update().
		Where(user.ID(id), user.PasswordHash(old)).
		SetPasswordHash(next).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
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
		ID:              e.ID,
		RealmID:         e.RealmID,
		Username:        e.Username,
		Email:           e.Email,
		EmailVerifiedAt: e.EmailVerifiedAt,
		PendingEmail:    e.PendingEmail,
		PasswordHash:    e.PasswordHash,
		CreatedAt:       e.CreatedAt,

		PasswordChangedAt: e.PasswordChangedAt,
		PasswordHistory:   e.PasswordHistory,
		UpdatedAt:         e.UpdatedAt,
		DeletedAt:         e.DeletedAt,
		Status:            domain.UserStatus(e.Status),
		LastLoginAt:       e.LastLoginAt,
		Profile:           e.Profile,
		Lockout:           lockoutFromEnt(e),

		MustChangePassword:  e.MustChangePassword,
		DeletionScheduledAt: e.DeletionScheduledAt,
	}
}
