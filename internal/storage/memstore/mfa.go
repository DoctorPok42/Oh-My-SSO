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

// --- MfaMethods ------------------------------------------------------------------

// MfaMethods implements repository.MfaMethodRepository, including the
// "one active TOTP per user" rule of the partial unique index.
type MfaMethods struct {
	mu      sync.Mutex
	methods []*domain.MfaMethod
	Now     func() time.Time
}

var _ repository.MfaMethodRepository = (*MfaMethods)(nil)

func NewMfaMethods(now func() time.Time) *MfaMethods {
	if now == nil {
		now = time.Now
	}
	return &MfaMethods{Now: now}
}

func (s *MfaMethods) Create(_ context.Context, p repository.CreateMfaMethodParams) (*domain.MfaMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := p.Status
	if status == "" {
		status = domain.MfaMethodActive
	}
	now := s.Now()
	m := &domain.MfaMethod{
		ID: uuid.NewString(), UserID: p.UserID, Type: p.Type, Name: p.Name, Status: status,
		SecretEncrypted: p.SecretEncrypted, CredentialID: p.CredentialID, PublicKey: p.PublicKey,
		IsDiscoverable: p.IsDiscoverable, WebAuthnCredential: p.WebAuthnCredential, CreatedAt: now, UpdatedAt: now,
	}
	for _, o := range s.methods {
		if p.CredentialID != "" && o.CredentialID == p.CredentialID {
			return nil, repository.ErrConflict
		}
	}
	s.methods = append(s.methods, m)
	cp := *m
	return &cp, nil
}

func (s *MfaMethods) find(id string) *domain.MfaMethod {
	for _, m := range s.methods {
		if m.ID == id {
			return m
		}
	}
	return nil
}

func (s *MfaMethods) GetByID(_ context.Context, id string) (*domain.MfaMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.find(id); m != nil {
		cp := *m
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (s *MfaMethods) ListByUser(_ context.Context, userID string) ([]*domain.MfaMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.MfaMethod
	for _, m := range s.methods {
		if m.UserID == userID {
			cp := *m
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MfaMethods) Update(_ context.Context, id string, p repository.UpdateMfaMethodParams) (*domain.MfaMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.find(id)
	if m == nil {
		return nil, repository.ErrNotFound
	}
	if p.Status != nil {
		m.Status = *p.Status
	}
	if p.Name != nil {
		m.Name = *p.Name
	}
	m.UpdatedAt = s.Now()
	cp := *m
	return &cp, nil
}

func (s *MfaMethods) MarkUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.find(id)
	if m == nil {
		return repository.ErrNotFound
	}
	m.LastUsedAt = s.Now()
	return nil
}

func (s *MfaMethods) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.methods)
	s.methods = slices.DeleteFunc(s.methods, func(m *domain.MfaMethod) bool { return m.ID == id })
	if len(s.methods) == before {
		return repository.ErrNotFound
	}
	return nil
}

func (s *MfaMethods) ActivateTOTP(_ context.Context, id string, counter int64, at time.Time) (*domain.MfaMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.find(id)
	if m == nil || m.Type != domain.MfaMethodTOTP || m.Status != domain.MfaMethodPending {
		return nil, repository.ErrNotFound
	}
	s.methods = slices.DeleteFunc(s.methods, func(o *domain.MfaMethod) bool {
		return o.UserID == m.UserID && o.Type == domain.MfaMethodTOTP && o.Status == domain.MfaMethodActive && o.ID != id
	})
	m.Status = domain.MfaMethodActive
	m.LastUsedCounter = counter
	m.LastUsedAt = at
	m.UpdatedAt = s.Now()
	cp := *m
	return &cp, nil
}

func (s *MfaMethods) ConsumeTOTPCounter(_ context.Context, id string, counter int64, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.find(id)
	if m == nil || m.Status != domain.MfaMethodActive || m.LastUsedCounter >= counter {
		return false, nil
	}
	m.LastUsedCounter = counter
	m.LastUsedAt = at
	return true, nil
}

func (s *MfaMethods) DeletePendingByUser(_ context.Context, userID string, t domain.MfaMethodType) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.methods)
	s.methods = slices.DeleteFunc(s.methods, func(m *domain.MfaMethod) bool {
		return m.UserID == userID && m.Type == t && m.Status == domain.MfaMethodPending
	})
	return before - len(s.methods), nil
}

func (s *MfaMethods) UpdateWebAuthnCredential(_ context.Context, id string, credentialJSON string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.find(id)
	if m == nil {
		return repository.ErrNotFound
	}
	m.WebAuthnCredential = credentialJSON
	m.LastUsedAt = at
	return nil
}

func (s *MfaMethods) DeleteByUser(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.methods)
	s.methods = slices.DeleteFunc(s.methods, func(m *domain.MfaMethod) bool { return m.UserID == userID })
	return before - len(s.methods), nil
}

// --- MfaBackupCodes ---------------------------------------------------------------

// MfaBackupCodes implements repository.MfaBackupCodeRepository.
type MfaBackupCodes struct {
	mu    sync.Mutex
	codes []*domain.MfaBackupCode
	Now   func() time.Time
}

var _ repository.MfaBackupCodeRepository = (*MfaBackupCodes)(nil)

func NewMfaBackupCodes(now func() time.Time) *MfaBackupCodes {
	if now == nil {
		now = time.Now
	}
	return &MfaBackupCodes{Now: now}
}

func (s *MfaBackupCodes) Create(_ context.Context, p repository.CreateMfaBackupCodeParams) (*domain.MfaBackupCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	c := &domain.MfaBackupCode{ID: uuid.NewString(), UserID: p.UserID, BatchID: p.BatchID, CodeHash: p.CodeHash, CreatedAt: now, UpdatedAt: now}
	s.codes = append(s.codes, c)
	cp := *c
	return &cp, nil
}

func (s *MfaBackupCodes) GetByID(_ context.Context, id string) (*domain.MfaBackupCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.codes {
		if c.ID == id {
			cp := *c
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (s *MfaBackupCodes) list(keep func(*domain.MfaBackupCode) bool) []*domain.MfaBackupCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.MfaBackupCode
	for _, c := range s.codes {
		if keep(c) {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out
}

func (s *MfaBackupCodes) ListByUser(_ context.Context, userID string) ([]*domain.MfaBackupCode, error) {
	return s.list(func(c *domain.MfaBackupCode) bool { return c.UserID == userID }), nil
}

func (s *MfaBackupCodes) ListByBatch(_ context.Context, userID, batchID string) ([]*domain.MfaBackupCode, error) {
	return s.list(func(c *domain.MfaBackupCode) bool { return c.UserID == userID && c.BatchID == batchID }), nil
}

func (s *MfaBackupCodes) ListUnusedByUser(_ context.Context, userID string) ([]*domain.MfaBackupCode, error) {
	return s.list(func(c *domain.MfaBackupCode) bool { return c.UserID == userID && !c.Used }), nil
}

func (s *MfaBackupCodes) GetByCodeHash(_ context.Context, codeHash string) (*domain.MfaBackupCode, error) {
	got := s.list(func(c *domain.MfaBackupCode) bool { return c.CodeHash == codeHash })
	if len(got) == 0 {
		return nil, repository.ErrNotFound
	}
	return got[0], nil
}

func (s *MfaBackupCodes) MarkUsed(ctx context.Context, id string) error {
	_, err := s.ConsumeIfUnused(ctx, id)
	return err
}

func (s *MfaBackupCodes) ConsumeIfUnused(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.codes {
		if c.ID == id {
			if c.Used {
				return false, nil
			}
			c.Used, c.UsedAt = true, s.Now()
			return true, nil
		}
	}
	return false, nil
}

func (s *MfaBackupCodes) ReplaceForUser(_ context.Context, userID, batchID string, codeHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes = slices.DeleteFunc(s.codes, func(c *domain.MfaBackupCode) bool { return c.UserID == userID })
	now := s.Now()
	for _, h := range codeHashes {
		s.codes = append(s.codes, &domain.MfaBackupCode{ID: uuid.NewString(), UserID: userID, BatchID: batchID, CodeHash: h, CreatedAt: now, UpdatedAt: now})
	}
	return nil
}

func (s *MfaBackupCodes) DeleteByBatch(_ context.Context, userID, batchID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes = slices.DeleteFunc(s.codes, func(c *domain.MfaBackupCode) bool { return c.UserID == userID && c.BatchID == batchID })
	return nil
}

func (s *MfaBackupCodes) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.codes)
	s.codes = slices.DeleteFunc(s.codes, func(c *domain.MfaBackupCode) bool { return c.ID == id })
	if len(s.codes) == before {
		return repository.ErrNotFound
	}
	return nil
}

func (s *MfaBackupCodes) DeleteByUser(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.codes)
	s.codes = slices.DeleteFunc(s.codes, func(c *domain.MfaBackupCode) bool { return c.UserID == userID })
	return before - len(s.codes), nil
}

// --- MfaPolicies ------------------------------------------------------------------

// MfaPolicies implements repository.MfaPolicyRepository.
type MfaPolicies struct {
	mu       sync.Mutex
	policies []*domain.MfaPolicy
	Now      func() time.Time
}

var _ repository.MfaPolicyRepository = (*MfaPolicies)(nil)

func NewMfaPolicies(now func() time.Time) *MfaPolicies {
	if now == nil {
		now = time.Now
	}
	return &MfaPolicies{Now: now}
}

func (s *MfaPolicies) Upsert(_ context.Context, p repository.UpsertMfaPolicyParams) (*domain.MfaPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	managedBy := p.ManagedBy
	if managedBy == "" {
		managedBy = domain.MfaPolicyManagedByUI
	}
	now := s.Now()
	for _, e := range s.policies {
		if e.RoleID == p.RoleID {
			e.ManagedBy, e.Required, e.AllowedMethods = managedBy, p.Required, slices.Clone(p.AllowedMethods)
			e.EnrollmentGraceDays, e.StepUpForSensitiveActions, e.RequiredSince = p.EnrollmentGraceDays, p.StepUpForSensitiveActions, p.RequiredSince
			e.UpdatedAt = now
			cp := *e
			return &cp, nil
		}
	}
	e := &domain.MfaPolicy{
		ID: uuid.NewString(), RealmID: p.RealmID, RoleID: p.RoleID, ManagedBy: managedBy,
		Required: p.Required, AllowedMethods: slices.Clone(p.AllowedMethods),
		EnrollmentGraceDays: p.EnrollmentGraceDays, StepUpForSensitiveActions: p.StepUpForSensitiveActions,
		RequiredSince: p.RequiredSince, CreatedAt: now, UpdatedAt: now,
	}
	s.policies = append(s.policies, e)
	cp := *e
	return &cp, nil
}

func (s *MfaPolicies) GetByRole(_ context.Context, roleID string) (*domain.MfaPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.policies {
		if e.RoleID == roleID {
			cp := *e
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (s *MfaPolicies) ListByRealm(_ context.Context, realmID string) ([]*domain.MfaPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.MfaPolicy
	for _, e := range s.policies {
		if e.RealmID == realmID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MfaPolicies) ListByRoleIDs(_ context.Context, roleIDs []string) ([]*domain.MfaPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.MfaPolicy
	for _, e := range s.policies {
		if slices.Contains(roleIDs, e.RoleID) {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MfaPolicies) DeleteByRole(_ context.Context, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.policies)
	s.policies = slices.DeleteFunc(s.policies, func(e *domain.MfaPolicy) bool { return e.RoleID == roleID })
	if len(s.policies) == before {
		return repository.ErrNotFound
	}
	return nil
}
