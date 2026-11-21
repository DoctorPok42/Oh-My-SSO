package service_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

func (m *memUsers) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return repository.ErrNotFound
	}
	delete(m.byID, id)
	return nil
}

// acctErasure is ErasureRepository on memUsers; EraseTraces only records.
type acctErasure struct {
	users  *memUsers
	mu     sync.Mutex
	erased []string
}

func (e *acctErasure) ScheduleDeletion(_ context.Context, userID string, at *time.Time) error {
	e.users.mu.Lock()
	defer e.users.mu.Unlock()
	u, ok := e.users.byID[userID]
	if !ok {
		return repository.ErrNotFound
	}
	u.DeletionScheduledAt = nil
	if at != nil {
		cp := *at
		u.DeletionScheduledAt = &cp
	}
	return nil
}

func (e *acctErasure) DeletionDue(_ context.Context, before time.Time, limit int) ([]*domain.User, error) {
	e.users.mu.Lock()
	defer e.users.mu.Unlock()
	var out []*domain.User
	for _, u := range e.users.byID {
		if u.DeletionScheduledAt != nil && u.DeletionScheduledAt.Before(before) && len(out) < limit {
			cp := *u
			out = append(out, &cp)
		}
	}
	return out, nil
}

// EraseAccount: the same condition as the database (gone, or no longer due:
// nothing happens).
func (e *acctErasure) EraseAccount(_ context.Context, u *domain.User, dueBy *time.Time) (bool, error) {
	e.users.mu.Lock()
	defer e.users.mu.Unlock()
	cur, ok := e.users.byID[u.ID]
	if !ok || (dueBy != nil && (cur.DeletionScheduledAt == nil || cur.DeletionScheduledAt.After(*dueBy))) {
		return false, nil
	}
	delete(e.users.byID, u.ID)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.erased = append(e.erased, u.ID)
	return true, nil
}

// acctSettings: the realm's settings, account deletion on or off.
type acctSettings struct {
	repository.InstanceSettingsRepository
	deletion bool
}

func (s acctSettings) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	st := service.DefaultInstanceSettings(realmID)
	st.AccountDeletionEnabled = s.deletion
	return st, nil
}

type deletionFixture struct {
	*acctFixture
	erasure *service.ErasureService
	store   *acctErasure
}

func newDeletionFixture(t *testing.T, allowed bool) *deletionFixture {
	d := &deletionFixture{}
	d.acctFixture = newAcctFixture(t, func(f *acctFixture, deps *service.AccountDeps) {
		d.store = &acctErasure{users: f.users}
		d.erasure = service.NewErasureService(service.ErasureDeps{
			Users: f.users, Erasure: d.store, Sessions: f.sessSvc, Consents: f.consents, Clients: f.clients,
			Audit: f.audit, Now: f.clock.Now,
		})
		deps.Erasure, deps.Settings = d.erasure, acctSettings{deletion: allowed}
	})
	return d
}

var acmeRealm = &domain.Realm{ID: acctRealm, Name: "acme"}

func TestAccount_Deletion(t *testing.T) {
	f := newDeletionFixture(t, true)
	ctx := context.Background()
	sess := f.session(t, f.user)
	f.consents.rows["consent-1"] = &domain.Consent{ID: "consent-1", UserID: f.user.ID, ClientRefID: "c-payroll",
		Scopes: []string{"openid"}, Status: domain.ConsentGranted, GrantedAt: f.clock.Now()}
	require.True(t, f.svc.AccountDeletionAllowed(ctx, acmeRealm))

	at, err := f.svc.RequestDeletion(ctx, acmeRealm, f.users.get(f.user.ID), ev)
	require.NoError(t, err)
	require.Equal(t, f.clock.Now().Add(service.AccountDeletionDelay), at)
	require.Equal(t, at, *f.users.get(f.user.ID).DeletionScheduledAt)
	require.Equal(t, domain.SessionRevoked, f.sessions.byID[sess.ID].Status, "signed out everywhere")
	mail := f.notifier.last()
	require.Equal(t, domain.NotificationAccountDeletionScheduled, mail.Kind)
	require.Equal(t, at, mail.ExpiresAt)

	f.clock.Advance(time.Hour)
	again, err := f.svc.RequestDeletion(ctx, acmeRealm, f.users.get(f.user.ID), ev)
	require.NoError(t, err)
	require.Equal(t, at, again, "asked again: the first date stays")

	require.NoError(t, f.svc.CancelDeletion(ctx, f.users.get(f.user.ID), ev))
	require.Nil(t, f.users.get(f.user.ID).DeletionScheduledAt)
	require.ErrorIs(t, f.svc.CancelDeletion(ctx, f.users.get(f.user.ID), ev), service.ErrAccountDeletionNotScheduled)
	require.Equal(t, []string{"user.deletion_requested:success", "user.deletion_cancelled:success"}, f.actions())

	// Asked again, and this time kept to the end.
	_, err = f.svc.RequestDeletion(ctx, acmeRealm, f.users.get(f.user.ID), ev)
	require.NoError(t, err)
	f.clock.Advance(service.AccountDeletionDelay - time.Minute)
	n, err := f.erasure.DeleteDue(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "not yet")
	f.clock.Advance(2 * time.Minute)
	n, err = f.erasure.DeleteDue(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = f.users.GetByID(ctx, f.user.ID)
	require.ErrorIs(t, err, repository.ErrNotFound)
	require.Equal(t, []string{f.user.ID}, f.store.erased, "its traces are erased")
	_, err = f.users.GetByID(ctx, f.other.ID)
	require.NoError(t, err, "nobody else")

	f.audit.mu.Lock()
	last := f.audit.entries[len(f.audit.entries)-1]
	f.audit.mu.Unlock()
	require.Equal(t, audit.UserDeleted, last.Action)
	require.Equal(t, domain.AuditActorSystem, last.ActorType)
	require.Equal(t, f.user.ID, last.TargetUserID, "the id stays: what happened stays visible")
	require.Equal(t, "user_request", last.Details["reason"])
	require.Equal(t, []string{"Payroll"}, last.Details["applications"], "who to tell (GDPR article 19)")
	require.NotContains(t, last.Details, "username")
	require.NotContains(t, last.Details, "email")

	n, err = f.erasure.DeleteDue(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "once")
}

func TestAccount_Deletion_NotAllowed(t *testing.T) {
	ctx := context.Background()

	off := newDeletionFixture(t, false)
	require.False(t, off.svc.AccountDeletionAllowed(ctx, acmeRealm))
	_, err := off.svc.RequestDeletion(ctx, acmeRealm, off.users.get(off.user.ID), ev)
	require.ErrorIs(t, err, service.ErrAccountDeletionDisabled)
	require.Nil(t, off.users.get(off.user.ID).DeletionScheduledAt)

	on := newDeletionFixture(t, true)
	master := &domain.Realm{ID: acctRealm, Name: service.MasterRealmName}
	require.False(t, on.svc.AccountDeletionAllowed(ctx, master), "never in the master realm")
	_, err = on.svc.RequestDeletion(ctx, master, on.users.get(on.user.ID), ev)
	require.ErrorIs(t, err, service.ErrAccountDeletionDisabled)
}

// staleDue answers DeletionDue with a list read before the user cancelled.
type staleDue struct {
	*acctErasure
	due []*domain.User
}

func (s staleDue) DeletionDue(context.Context, time.Time, int) ([]*domain.User, error) {
	return s.due, nil
}

func TestErasure_DeleteDue_KeepsWhatWasCancelled(t *testing.T) {
	f := newDeletionFixture(t, true)
	ctx := context.Background()
	past := f.clock.Now().Add(-time.Hour)
	require.NoError(t, f.store.ScheduleDeletion(ctx, f.user.ID, &past))
	due, err := f.store.DeletionDue(ctx, f.clock.Now(), 10)
	require.NoError(t, err)
	require.Len(t, due, 1)
	// Cancelled between the list and its turn: DeleteDue reads it again.
	require.NoError(t, f.store.ScheduleDeletion(ctx, f.user.ID, nil))
	svc := service.NewErasureService(service.ErasureDeps{
		Users: f.users, Erasure: staleDue{f.store, due}, Sessions: f.sessSvc, Audit: f.audit, Now: f.clock.Now,
	})

	n, err := svc.DeleteDue(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	_, err = f.users.GetByID(ctx, f.user.ID)
	require.NoError(t, err, "kept")
	require.Empty(t, f.store.erased)
}
