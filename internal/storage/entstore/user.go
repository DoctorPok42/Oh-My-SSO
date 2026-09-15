package entstore

import (
	"context"

	"sso.internal/sso/ent"
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
	e, err := r.client.User.
		Create().
		SetRealmID(p.RealmID).
		SetUsername(p.Username).
		SetEmail(p.Email).
		SetPasswordHash(p.PasswordHash).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	e, err := r.client.User.Get(ctx, id)
	if err != nil {
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

	e, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainUser(e), nil
}

func (r *entUserRepository) Delete(ctx context.Context, id string) error {
	return r.client.User.DeleteOneID(id).Exec(ctx)
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
	}
}
