package service_test

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// In-memory fakes for the Step 12 tests (password reset, lockout, sign-in
// analysis). Same rule as the other fakes: the embedded interface is nil,
// so an unexpected call panics.

// testClock is a settable clock shared by the services under test.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// memUsers stores users and supports password updates and the lockout CAS.
type memUsers struct {
	repository.UserRepository
	mu   sync.Mutex
	byID map[string]*domain.User
}

func newMemUsers(users ...*domain.User) *memUsers {
	m := &memUsers{byID: map[string]*domain.User{}}
	for _, u := range users {
		m.byID[u.ID] = u
	}
	return m
}

func (m *memUsers) get(id string) *domain.User {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *m.byID[id]
	return &cp
}

func (m *memUsers) GetByID(_ context.Context, id string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *memUsers) find(match func(*domain.User) bool) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.byID {
		if match(u) {
			cp := *u
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *memUsers) GetByRealmAndUsername(_ context.Context, realmID, username string) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.RealmID == realmID && u.Username == username })
}

func (m *memUsers) GetByRealmAndEmail(_ context.Context, realmID, email string) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.RealmID == realmID && u.Email == email })
}

func (m *memUsers) Update(_ context.Context, id string, p repository.UpdateUserParams) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if p.PasswordHash != nil {
		u.PasswordHash = *p.PasswordHash
	}
	if p.Status != nil {
		u.Status = *p.Status
	}
	cp := *u
	return &cp, nil
}

func (m *memUsers) CompareAndSwapLockout(_ context.Context, id string, old, next domain.LockoutState) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return false, repository.ErrNotFound
	}
	if !sameLockout(u.Lockout, old) {
		return false, nil
	}
	u.Lockout = next
	return true, nil
}

func sameLockout(a, b domain.LockoutState) bool {
	return a.FailedCount == b.FailedCount && a.LockCount == b.LockCount &&
		a.LastFailedAt.Equal(b.LastFailedAt) && a.LockedUntil.Equal(b.LockedUntil) && a.LastLockedAt.Equal(b.LastLockedAt)
}

// memResetTokens is a PasswordResetTokenRepository in memory.
type memResetTokens struct {
	repository.PasswordResetTokenRepository
	mu   sync.Mutex
	seq  int
	byID map[string]*domain.PasswordResetToken
}

func newMemResetTokens() *memResetTokens {
	return &memResetTokens{byID: map[string]*domain.PasswordResetToken{}}
}

func (m *memResetTokens) Create(_ context.Context, p repository.CreatePasswordResetTokenParams) (*domain.PasswordResetToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	t := &domain.PasswordResetToken{
		ID: fmt.Sprintf("prt-%d", m.seq), UserID: p.UserID, TokenHash: p.TokenHash,
		ExpiresAt: p.ExpiresAt, RequestedIP: p.RequestedIP,
	}
	m.byID[t.ID] = t
	cp := *t
	return &cp, nil
}

func (m *memResetTokens) GetByTokenHash(_ context.Context, hash string) (*domain.PasswordResetToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.byID {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *memResetTokens) ConsumeIfUnused(_ context.Context, id string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byID[id]
	if !ok || t.Used {
		return false, nil
	}
	t.Used, t.UsedAt = true, at
	return true, nil
}

func (m *memResetTokens) DeleteUnusedByUser(_ context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, t := range m.byID {
		if t.UserID == userID && !t.Used {
			delete(m.byID, id)
			n++
		}
	}
	return n, nil
}

func (m *memResetTokens) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}

// memSettings returns one InstanceSettings for every realm (nil: not found).
type memSettings struct {
	repository.InstanceSettingsRepository
	mu sync.Mutex
	s  *domain.InstanceSettings
}

func (m *memSettings) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.s == nil {
		return nil, repository.ErrNotFound
	}
	cp := *m.s
	cp.RealmID = realmID
	return &cp, nil
}

// recordingNotifier keeps every event.
type recordingNotifier struct {
	mu     sync.Mutex
	events []domain.NotificationEvent
}

func (r *recordingNotifier) Notify(_ context.Context, e domain.NotificationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingNotifier) kinds() []domain.NotificationKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.NotificationKind, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Kind)
	}
	return out
}

func (r *recordingNotifier) last() domain.NotificationEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events[len(r.events)-1]
}

// memSessionHistory is a SessionRepository with history (ListRecentByUser).
type memSessionHistory struct {
	repository.SessionRepository
	mu   sync.Mutex
	list []*domain.Session
}

func (m *memSessionHistory) add(s *domain.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.list = append(m.list, s)
}

func (m *memSessionHistory) ListRecentByUser(_ context.Context, userID string, since time.Time, limit int) ([]*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*domain.Session
	for _, s := range m.list {
		if s.UserID == userID && !s.CreatedAt.Before(since) {
			cp := *s
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
