package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// E-mail change by the user (account console), where the realm allows it
// (email_change_allowed, off by default). The new address is only pending
// (users.pending_email) until the link e-mailed to it is used: then it
// becomes the account's address, verified, and the previous address is told.
// Until then, applications keep seeing the previous one: one that matches
// accounts by address never gets an unproven address. Only one link lives
// per account: a new verification e-mail, or a change by an administrator,
// cancels the pending change.

var (
	ErrEmailChangeNotAllowed = errors.New("service: this organization does not let users change their e-mail address")
	ErrInvalidEmail          = errors.New("service: not a plain e-mail address")
	ErrEmailUnchanged        = errors.New("service: this already is the account's address")
	// ErrEmailTaken: another account of the realm signs in with this
	// address (as its address or its username).
	ErrEmailTaken = errors.New("service: the e-mail address is already used in this realm")
)

// EmailChangeAllowed tells whether the realm lets its users change their
// address, and e-mails can leave (the new address must be confirmed).
func (s *EmailVerificationService) EmailChangeAllowed(ctx context.Context, realmID string) bool {
	if !s.Enabled() || s.settings == nil {
		return false
	}
	return s.settings.get(ctx, realmID).EmailChangeAllowed
}

// RequestEmailChange makes newEmail the account's pending address and
// e-mails a link to it. It returns when the link expires.
func (s *EmailVerificationService) RequestEmailChange(ctx context.Context, user *domain.User, newEmail string, by VerificationRequester) (time.Time, error) {
	if !s.EmailChangeAllowed(ctx, user.RealmID) {
		return time.Time{}, ErrEmailChangeNotAllowed
	}
	if user.Status != domain.UserActive {
		return time.Time{}, ErrEmailVerificationUnavailable
	}
	addr, err := mail.ParseAddress(strings.TrimSpace(newEmail))
	if err != nil || addr.Name != "" || len(addr.Address) > 320 {
		return time.Time{}, ErrInvalidEmail
	}
	email := domain.NormalizeIdentifier(addr.Address)
	if email == user.Email {
		return time.Time{}, ErrEmailUnchanged
	}
	// One link a minute. The callers limit the requests themselves: a taken
	// address makes no link, so this alone does not stop probing the realm.
	if err := s.cooldown(ctx, user.ID); err != nil {
		return time.Time{}, err
	}
	taken, err := identifierTaken(ctx, s.d.Users, user.RealmID, user.ID, email)
	if err != nil {
		return time.Time{}, fmt.Errorf("email change: %w", err)
	}
	if taken {
		return time.Time{}, ErrEmailTaken
	}
	expires, err := s.mailLink(ctx, user, email, email, by)
	if err != nil {
		return time.Time{}, err
	}
	s.audit(ctx, user, by, audit.UserEmailChangeRequested, map[string]interface{}{
		"email": email, "expires_at": expires.UTC().Format(time.RFC3339),
	})
	return expires, nil
}

// CancelEmailChange forgets the pending address and its link. Nothing
// pending: nothing to do.
func (s *EmailVerificationService) CancelEmailChange(ctx context.Context, user *domain.User, by VerificationRequester) error {
	if user.PendingEmail == "" {
		return nil
	}
	none := ""
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.d.Links.DeleteUnusedByUser(ctx, user.ID); err != nil {
			return fmt.Errorf("email change: cancel link: %w", err)
		}
		if _, err := s.d.Users.Update(ctx, user.ID, repository.UpdateUserParams{PendingEmail: &none}); err != nil {
			return fmt.Errorf("email change: cancel: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.audit(ctx, user, by, audit.UserEmailChangeCancelled, map[string]interface{}{"email": user.PendingEmail})
	return nil
}

// applyChange uses a link sent to the pending address (Verify): the account
// switches to it, verified, and the previous address gets an e-mail.
func (s *EmailVerificationService) applyChange(ctx context.Context, user *domain.User, tok *domain.EmailVerificationToken, ip, userAgent string) (*domain.User, error) {
	// Turned off since the request, or the address was taken meanwhile: the
	// link proves nothing any more (asking again tells why).
	if !s.EmailChangeAllowed(ctx, user.RealmID) {
		return nil, ErrEmailVerificationInvalid
	}
	if taken, err := identifierTaken(ctx, s.d.Users, user.RealmID, user.ID, tok.Email); err != nil {
		return nil, fmt.Errorf("email change: %w", err)
	} else if taken {
		return nil, ErrEmailVerificationInvalid
	}
	now := s.d.Now()
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		used, err := s.d.Links.Consume(ctx, tok.ID, now)
		if err != nil {
			return fmt.Errorf("email change: use link: %w", err)
		}
		if !used {
			return ErrEmailVerificationInvalid // another request used it a moment ago
		}
		applied, err := s.d.Links.ApplyEmailChange(ctx, user.ID, tok.Email, now)
		if errors.Is(err, repository.ErrConflict) {
			return ErrEmailVerificationInvalid
		}
		if err != nil {
			return fmt.Errorf("email change: apply: %w", err)
		}
		if !applied {
			return ErrEmailVerificationInvalid // cancelled or replaced a moment ago
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	fresh, err := s.d.Users.GetByID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("email change: reload user: %w", err)
	}
	s.d.Notifier.Notify(ctx, domain.NotificationEvent{
		Kind: domain.NotificationEmailChanged, RealmID: user.RealmID, UserID: user.ID, To: user.Email,
		OccurredAt: now, IPAddress: ip, UserAgent: userAgent,
	})
	// "email": deleting the account erases it from the entries about the
	// account, whatever the address (entstore eraser, ownKeys).
	s.audit(ctx, fresh, VerificationRequester{ActorType: domain.AuditActorUser, ActorID: user.ID, IPAddress: ip, UserAgent: userAgent},
		audit.UserEmailChanged, map[string]interface{}{"email": fresh.Email})
	return fresh, nil
}
