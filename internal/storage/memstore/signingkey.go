// Package memstore holds in-memory implementations of some repositories.
//
// They exist for tests: they let a test run the real services (key rotation,
// JWKS, IdentityCore.Signer) without Postgres. They follow the same rules as
// the Ent implementations (conditional updates, ErrNotFound, copies instead
// of shared pointers) so that a test passing here means something.
//
// Never use them in cmd/: nothing survives a restart.
package memstore

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// SigningKeys implements repository.SigningKeyRepository.
type SigningKeys struct {
	mu   sync.Mutex
	keys []*domain.SigningKey
	// Now stamps CreatedAt / UpdatedAt / RetiredAt. Defaults to time.Now;
	// tests share their fake clock with it.
	Now func() time.Time
}

var _ repository.SigningKeyRepository = (*SigningKeys)(nil)

func NewSigningKeys(now func() time.Time) *SigningKeys {
	if now == nil {
		now = time.Now
	}
	return &SigningKeys{Now: now}
}

// Add stores a key as-is (test setup: any status, any date).
func (s *SigningKeys) Add(k *domain.SigningKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *k
	if cp.ID == "" {
		cp.ID = uuid.NewString()
	}
	s.keys = append(s.keys, &cp)
}

func (s *SigningKeys) Create(_ context.Context, p repository.CreateSigningKeyParams) (*domain.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	status := p.Status
	if status == "" {
		status = domain.SigningKeyActive
	}
	k := &domain.SigningKey{
		ID: uuid.NewString(), RealmID: p.RealmID, KeyType: p.KeyType, Purpose: p.Purpose,
		KMSKeyReference: p.KMSKeyReference, KMSBackend: p.KMSBackend, PublicKey: p.PublicKey,
		Kid: p.Kid, Status: status, CreatedAt: now, UpdatedAt: now, Certificate: p.Certificate,
	}
	s.keys = append(s.keys, k)
	cp := *k
	return &cp, nil
}

func (s *SigningKeys) GetByID(_ context.Context, id string) (*domain.SigningKey, error) {
	return s.find(func(k *domain.SigningKey) bool { return k.ID == id })
}

func (s *SigningKeys) GetByKid(_ context.Context, kid string) (*domain.SigningKey, error) {
	return s.find(func(k *domain.SigningKey) bool { return k.Kid == kid })
}

func (s *SigningKeys) ListActiveByRealm(_ context.Context, realmID string) ([]*domain.SigningKey, error) {
	return s.list(func(k *domain.SigningKey) bool {
		return k.RealmID == realmID && (k.Status == domain.SigningKeyPending ||
			k.Status == domain.SigningKeyActive || k.Status == domain.SigningKeyRotating)
	}), nil
}

func (s *SigningKeys) ListByRealm(_ context.Context, realmID string) ([]*domain.SigningKey, error) {
	out := s.list(func(k *domain.SigningKey) bool { return k.RealmID == realmID })
	slices.SortStableFunc(out, func(a, b *domain.SigningKey) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (s *SigningKeys) SetStatus(_ context.Context, id string, status domain.SigningKeyStatus) error {
	return s.update(id, func(*domain.SigningKey) bool { return true }, func(k *domain.SigningKey) {
		k.Status = status
	})
}

func (s *SigningKeys) MarkRotating(_ context.Context, id string, retireAfter time.Time) error {
	return s.update(id,
		func(k *domain.SigningKey) bool { return k.Status == domain.SigningKeyActive },
		func(k *domain.SigningKey) { k.Status, k.RetireAfter = domain.SigningKeyRotating, retireAfter })
}

func (s *SigningKeys) Activate(_ context.Context, id string) error {
	return s.update(id,
		func(k *domain.SigningKey) bool { return k.Status == domain.SigningKeyPending },
		func(k *domain.SigningKey) { k.Status = domain.SigningKeyActive })
}

func (s *SigningKeys) Retire(_ context.Context, id string) error {
	return s.update(id,
		func(k *domain.SigningKey) bool { return k.Status != domain.SigningKeyRetired },
		func(k *domain.SigningKey) { k.Status, k.RetiredAt = domain.SigningKeyRetired, s.Now() })
}

func (s *SigningKeys) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.keys {
		if k.ID == id {
			s.keys = slices.Delete(s.keys, i, i+1)
			return nil
		}
	}
	return repository.ErrNotFound
}

func (s *SigningKeys) find(match func(*domain.SigningKey) bool) (*domain.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if match(k) {
			cp := *k
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (s *SigningKeys) list(match func(*domain.SigningKey) bool) []*domain.SigningKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.SigningKey
	for _, k := range s.keys {
		if match(k) {
			cp := *k
			out = append(out, &cp)
		}
	}
	return out
}

// update mimics "UPDATE ... WHERE id = $1 AND <cond>": ErrNotFound when no
// row matches, exactly like the Ent implementation.
func (s *SigningKeys) update(id string, cond func(*domain.SigningKey) bool, apply func(*domain.SigningKey)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.ID == id && cond(k) {
			apply(k)
			k.UpdatedAt = s.Now()
			return nil
		}
	}
	return repository.ErrNotFound
}
