package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Deleting an account for good (GDPR article 17), the same way whoever asks:
// an administrator now (AdminService.DeleteUser), or the user, after
// AccountDeletionDelay (account console, DeleteDue).
//
// What is erased: the account and every row that goes with it (sessions and
// tokens, second factors, consents, devices, e-mails waiting, copies of its
// data...), its sign-in attempts, and in what is kept for the others (audit
// log, reports of bulk actions and imports) its addresses, browsers, name and
// e-mail address. What stays: each entry's action, date and the account's id,
// which no longer leads to anyone. So the audit log still shows what was done,
// without telling who it was.

const (
	// AccountDeletionDelay: between the user's request and the deletion,
	// the time to change their mind (or to notice someone else asked).
	AccountDeletionDelay = 14 * 24 * time.Hour
	// erasureBatch: the accounts one pass deletes at most.
	erasureBatch = 100
	// erasureRecentSessions: the sessions looked at for the applications
	// that received the account's data.
	erasureRecentSessions = 1000
)

type ErasureDeps struct {
	Users    repository.UserRepository
	Erasure  repository.ErasureRepository
	Sessions *SessionService
	// For the applications that received the account's data (article 19):
	// its consents, and the clients of the tokens of its sessions.
	SessionRows repository.SessionRepository
	Tokens      repository.TokenRepository
	Consents    repository.ConsentRepository
	Clients     repository.ClientRepository
	Audit       repository.AuditLogRepository
	Logger      *slog.Logger
	Now         func() time.Time
}

type ErasureService struct {
	d ErasureDeps
}

func NewErasureService(d ErasureDeps) *ErasureService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &ErasureService{d: d}
}

// Schedule sets when the account is deleted; nil cancels.
func (s *ErasureService) Schedule(ctx context.Context, userID string, at *time.Time) error {
	return s.d.Erasure.ScheduleDeletion(ctx, userID, at)
}

// Erase deletes the account for good, now (an administrator). It returns the
// applications that received its data (for the audit entry: whoever runs the
// server tells them, article 19), and false when the account was already
// gone (another server was first): then the caller writes no entry.
func (s *ErasureService) Erase(ctx context.Context, u *domain.User) (apps []string, deleted bool, err error) {
	return s.erase(ctx, u, nil)
}

// erase: Erase; dueBy (DeleteDue): only if its owner-requested deletion is
// still due then, so that a cancel at the last moment wins.
func (s *ErasureService) erase(ctx context.Context, u *domain.User, dueBy *time.Time) ([]string, bool, error) {
	apps := s.recipients(ctx, u)
	// Before the transaction: a session store call holds no database lock.
	if err := s.d.Sessions.RevokeAllForUser(ctx, u.ID, domain.SessionRevokedAccountDeletion); err != nil {
		return nil, false, fmt.Errorf("erase account: sign out: %w", err)
	}
	deleted, err := s.d.Erasure.EraseAccount(ctx, u, dueBy)
	if err != nil {
		return nil, false, fmt.Errorf("erase account: %w", err)
	}
	return apps, deleted, nil
}

// recipients: the names of the applications the account used, best effort.
func (s *ErasureService) recipients(ctx context.Context, u *domain.User) []string {
	refs := map[string]bool{}
	if s.d.Consents != nil {
		consents, err := s.d.Consents.ListByUser(ctx, u.ID)
		if err != nil {
			s.d.Logger.WarnContext(ctx, "erase account: consents not listed", "user_id", u.ID, "error", err)
		}
		for _, c := range consents {
			refs[c.ClientRefID] = true
		}
	}
	if s.d.SessionRows != nil && s.d.Tokens != nil {
		sessions, err := s.d.SessionRows.ListRecentByUser(ctx, u.ID, time.Time{}, erasureRecentSessions)
		if err != nil {
			s.d.Logger.WarnContext(ctx, "erase account: sessions not listed", "user_id", u.ID, "error", err)
		}
		for _, se := range sessions {
			tokens, err := s.d.Tokens.ListBySession(ctx, se.ID)
			if err != nil {
				s.d.Logger.WarnContext(ctx, "erase account: tokens not listed", "user_id", u.ID, "error", err)
				break
			}
			for _, t := range tokens {
				refs[t.ClientRefID] = true
			}
		}
	}
	names := []string{}
	for ref := range refs {
		if ref == "" || s.d.Clients == nil {
			continue
		}
		if c, err := s.d.Clients.GetByID(ctx, ref); err == nil {
			names = append(names, clientDisplayName(c))
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// DeleteDue deletes the accounts whose deletion time came, and returns how
// many. Several servers may run it at once: an account is deleted, and its
// entry written, once.
func (s *ErasureService) DeleteDue(ctx context.Context) (int, error) {
	due, err := s.d.Erasure.DeletionDue(ctx, s.d.Now(), erasureBatch)
	if err != nil {
		return 0, fmt.Errorf("accounts due for deletion: %w", err)
	}
	n := 0
	var errs []error
	for _, u := range due {
		if ctx.Err() != nil {
			break
		}
		// Read again: the user may have cancelled since the list.
		cur, err := s.d.Users.GetByID(ctx, u.ID)
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		now := s.d.Now()
		if cur.DeletionScheduledAt == nil || cur.DeletionScheduledAt.After(now) {
			continue
		}
		apps, deleted, err := s.erase(ctx, cur, &now)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %s: %w", cur.ID, err))
			continue
		}
		if !deleted {
			continue
		}
		n++
		s.auditDeleted(ctx, cur, apps)
	}
	return n, errors.Join(errs...)
}

// auditDeleted: the entry of a deletion the user asked for. No name, no
// address: the id, when it was asked, and the applications to tell.
func (s *ErasureService) auditDeleted(ctx context.Context, u *domain.User, apps []string) {
	if s.d.Audit == nil {
		return
	}
	// Written even when the pass is stopping: the account is gone, its
	// trace must not be.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID: u.RealmID, ActorType: domain.AuditActorSystem, TargetUserID: u.ID,
		Action: audit.UserDeleted, ResourceType: "User", ResourceID: u.ID,
		Level: domain.AuditLogWarning, Status: domain.AuditLogSuccess,
		Details: map[string]interface{}{"reason": "user_request", "applications": apps},
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "erase account: user.deleted not written", "user_id", u.ID, "error", err)
	}
}
