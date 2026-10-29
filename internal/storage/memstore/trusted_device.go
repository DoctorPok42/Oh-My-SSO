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

// TrustedDevices implements repository.TrustedDeviceRepository in memory
// (tests).
type TrustedDevices struct {
	mu   sync.Mutex
	rows []*domain.TrustedDevice
}

var _ repository.TrustedDeviceRepository = (*TrustedDevices)(nil)

func NewTrustedDevices() *TrustedDevices { return &TrustedDevices{} }

func (s *TrustedDevices) Put(_ context.Context, p repository.PutTrustedDeviceParams) (*domain.TrustedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.rows {
		if d.UserID == p.UserID && d.DeviceHash == p.DeviceHash {
			// Like entstore: the row stays, a new period starts.
			if p.IPAddress != "" {
				d.IPAddress = p.IPAddress
			}
			if p.UserAgent != "" {
				d.UserAgent = p.UserAgent
			}
			d.CreatedAt, d.ExpiresAt, d.LastUsedAt = p.CreatedAt, p.ExpiresAt, time.Time{}
			cp := *d
			return &cp, nil
		}
	}
	d := &domain.TrustedDevice{
		ID: uuid.NewString(), RealmID: p.RealmID, UserID: p.UserID, DeviceHash: p.DeviceHash,
		IPAddress: p.IPAddress, UserAgent: p.UserAgent, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
	}
	s.rows = append(s.rows, d)
	cp := *d
	return &cp, nil
}

func (s *TrustedDevices) Get(_ context.Context, userID, deviceHash string) (*domain.TrustedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.rows {
		if d.UserID == userID && d.DeviceHash == deviceHash {
			cp := *d
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (s *TrustedDevices) MarkUsed(_ context.Context, id string, at time.Time, ip, userAgent string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.rows {
		if d.ID == id {
			d.LastUsedAt = at
			if ip != "" {
				d.IPAddress = ip
			}
			if userAgent != "" {
				d.UserAgent = userAgent
			}
			return nil
		}
	}
	return repository.ErrNotFound
}

func (s *TrustedDevices) ListByUser(_ context.Context, userID string, now time.Time) ([]*domain.TrustedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.TrustedDevice
	for _, d := range s.rows {
		if d.UserID == userID && d.Active(now) {
			cp := *d
			out = append(out, &cp)
		}
	}
	slices.SortStableFunc(out, func(a, b *domain.TrustedDevice) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (s *TrustedDevices) Delete(_ context.Context, id string) error {
	return s.deleteWhere(func(d *domain.TrustedDevice) bool { return d.ID == id }, true)
}

func (s *TrustedDevices) DeleteByUser(_ context.Context, userID string) (int, error) {
	return s.count(func(d *domain.TrustedDevice) bool { return d.UserID == userID })
}

func (s *TrustedDevices) DeleteByDevice(_ context.Context, userID, deviceHash string) (int, error) {
	return s.count(func(d *domain.TrustedDevice) bool { return d.UserID == userID && d.DeviceHash == deviceHash })
}

func (s *TrustedDevices) DeleteExpired(_ context.Context, userID string, now time.Time) (int, error) {
	return s.count(func(d *domain.TrustedDevice) bool { return d.UserID == userID && !d.Active(now) })
}

func (s *TrustedDevices) count(match func(*domain.TrustedDevice) bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.rows)
	s.rows = slices.DeleteFunc(s.rows, match)
	return before - len(s.rows), nil
}

func (s *TrustedDevices) deleteWhere(match func(*domain.TrustedDevice) bool, mustExist bool) error {
	n, _ := s.count(match)
	if n == 0 && mustExist {
		return repository.ErrNotFound
	}
	return nil
}
