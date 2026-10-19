package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type SigningKeyRepository interface {
	Create(ctx context.Context, p CreateSigningKeyParams) (*domain.SigningKey, error)
	GetByID(ctx context.Context, id string) (*domain.SigningKey, error)
	GetByKid(ctx context.Context, kid string) (*domain.SigningKey, error)
	// ListActiveByRealm returns the "pending", "active" and "rotating" keys
	// of a realm, i.e. every key whose public part is published. Only
	// "active" keys sign (see IdentityCore.Signer).
	ListActiveByRealm(ctx context.Context, realmID string) ([]*domain.SigningKey, error)
	// ListByRealm returns every key of a realm, retired ones included,
	// newest first (admin listing).
	ListByRealm(ctx context.Context, realmID string) ([]*domain.SigningKey, error)
	SetStatus(ctx context.Context, id string, status domain.SigningKeyStatus) error
	// MarkRotating moves an "active" key to "rotating" with its grace
	// deadline. It only touches a key that is still "active": it returns
	// ErrNotFound if the key does not exist or was already moved by a
	// concurrent rotation, so a retired key can never come back.
	MarkRotating(ctx context.Context, id string, retireAfter time.Time) error
	// Activate moves a "pending" key to "active" (Step 11). It only touches
	// a key that is still "pending": ErrNotFound otherwise.
	Activate(ctx context.Context, id string) error
	// Retire moves a "pending", "active" or "rotating" key to "retired".
	// Same ErrNotFound rule as MarkRotating if the key is already retired.
	Retire(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateSigningKeyParams struct {
	RealmID         string
	KeyType         domain.SigningKeyType
	Purpose         domain.SigningKeyPurpose
	KMSKeyReference string
	KMSBackend      string
	PublicKey       string
	Kid             string
	// Certificate: PEM X.509 certificate (saml_signing keys, Step 11).
	Certificate string
	// Status of the new key. Empty means "active".
	Status domain.SigningKeyStatus
}
