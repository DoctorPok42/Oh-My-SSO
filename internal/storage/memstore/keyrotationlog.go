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

// KeyRotationLogs implements repository.KeyRotationLogRepository.
type KeyRotationLogs struct {
	mu   sync.Mutex
	logs []*domain.KeyRotationLog
	Now  func() time.Time
}

var _ repository.KeyRotationLogRepository = (*KeyRotationLogs)(nil)

func NewKeyRotationLogs(now func() time.Time) *KeyRotationLogs {
	if now == nil {
		now = time.Now
	}
	return &KeyRotationLogs{Now: now}
}

func (s *KeyRotationLogs) Create(_ context.Context, p repository.CreateKeyRotationLogParams) (*domain.KeyRotationLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := &domain.KeyRotationLog{
		ID: uuid.NewString(), SigningKeyID: p.SigningKeyID, Action: p.Action,
		TriggeredBy: p.TriggeredBy, Reason: p.Reason, CreatedAt: s.Now(),
	}
	s.logs = append(s.logs, l)
	cp := *l
	return &cp, nil
}

func (s *KeyRotationLogs) GetByID(_ context.Context, id string) (*domain.KeyRotationLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.logs {
		if l.ID == id {
			cp := *l
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

// ListBySigningKey returns the logs of one key, newest first (like Ent).
func (s *KeyRotationLogs) ListBySigningKey(_ context.Context, signingKeyID string) ([]*domain.KeyRotationLog, error) {
	out := s.filter(func(l *domain.KeyRotationLog) bool { return l.SigningKeyID == signingKeyID })
	slices.Reverse(out)
	return out, nil
}

// All returns every log in insertion order (test assertions).
func (s *KeyRotationLogs) All() []*domain.KeyRotationLog {
	return s.filter(func(*domain.KeyRotationLog) bool { return true })
}

func (s *KeyRotationLogs) filter(match func(*domain.KeyRotationLog) bool) []*domain.KeyRotationLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.KeyRotationLog
	for _, l := range s.logs {
		if match(l) {
			cp := *l
			out = append(out, &cp)
		}
	}
	return out
}
