package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
)

// The user asks for their account to be deleted (account console, "Your
// data"), where the realm allows it (account_deletion_enabled, never the
// master realm). The account is deleted AccountDeletionDelay later
// (ErasureService.DeleteDue). Until then it is signed out everywhere,
// applications refuse it (IssueIdentityAssertion), and the user may sign in to
// the account console and cancel.

var (
	ErrAccountDeletionDisabled     = errors.New("service: this organization does not let accounts be deleted by their owner")
	ErrAccountDeletionNotScheduled = errors.New("service: the account is not waiting to be deleted")
)

// AccountDeletionAllowed tells whether the realm lets its users ask for the
// deletion of their account.
func (s *AccountService) AccountDeletionAllowed(ctx context.Context, realm *domain.Realm) bool {
	if s.d.Erasure == nil || realm.Name == MasterRealmName {
		return false
	}
	st := s.settings.get(ctx, realm.ID)
	return st != nil && st.AccountDeletionEnabled
}

// RequestDeletion schedules the deletion of the account, signs it out
// everywhere and tells the user by e-mail. Asked again, it keeps the first
// date.
func (s *AccountService) RequestDeletion(ctx context.Context, realm *domain.Realm, user *domain.User, ev AccountEvent) (time.Time, error) {
	if !s.AccountDeletionAllowed(ctx, realm) {
		return time.Time{}, ErrAccountDeletionDisabled
	}
	if user.DeletionScheduledAt != nil {
		return *user.DeletionScheduledAt, nil
	}
	now := s.d.Now()
	at := now.Add(AccountDeletionDelay)
	if err := s.d.Erasure.Schedule(ctx, user.ID, &at); err != nil {
		return time.Time{}, fmt.Errorf("request deletion: %w", err)
	}
	s.audit(ctx, user, audit.UserDeletionRequested, "User", user.ID, domain.AuditLogWarning, domain.AuditLogSuccess, ev,
		map[string]interface{}{"scheduled_for": at.UTC().Format(time.RFC3339)})
	// Applications lose their tokens with the sessions; the console signs
	// in again to cancel.
	if err := s.d.Sessions.RevokeAllForUser(ctx, user.ID, domain.SessionRevokedAccountDeletion); err != nil {
		s.d.Logger.WarnContext(ctx, "request deletion: sessions not revoked", "user_id", user.ID, "error", err)
	}
	s.d.Notifier.Notify(ctx, domain.NotificationEvent{
		Kind: domain.NotificationAccountDeletionScheduled, RealmID: user.RealmID, UserID: user.ID,
		OccurredAt: now, ExpiresAt: at, IPAddress: ev.IPAddress, UserAgent: ev.UserAgent,
	})
	return at, nil
}

// CancelDeletion keeps the account. Always possible, even once the realm
// stopped allowing deletions: nobody must be stuck half way.
func (s *AccountService) CancelDeletion(ctx context.Context, user *domain.User, ev AccountEvent) error {
	if user.DeletionScheduledAt == nil || s.d.Erasure == nil {
		return ErrAccountDeletionNotScheduled
	}
	if err := s.d.Erasure.Schedule(ctx, user.ID, nil); err != nil {
		return fmt.Errorf("cancel deletion: %w", err)
	}
	s.audit(ctx, user, audit.UserDeletionCancelled, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"scheduled_for": user.DeletionScheduledAt.UTC().Format(time.RFC3339)})
	return nil
}
