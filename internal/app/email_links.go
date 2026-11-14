package app

import (
	"context"
	"errors"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/storage/entstore"
)

// emailLinks tells the dispatcher what became of the links its e-mails
// carry (notify.LinkTracker): reset and activation links, address
// verification links.
type emailLinks struct {
	resets        repository.PasswordResetTokenRepository
	verifications repository.EmailVerificationRepository
	now           func() time.Time
}

// NewEmailLinks is the dispatcher's LinkTracker on the database.
func NewEmailLinks(client *ent.Client) notify.LinkTracker {
	return emailLinks{
		resets:        entstore.NewPasswordResetTokenRepository(client),
		verifications: entstore.NewEmailVerificationRepository(client),
		now:           time.Now,
	}
}

func (l emailLinks) Usable(ctx context.Context, kind domain.NotificationKind, token string) (bool, error) {
	hash := service.HashResetToken(token)
	now := l.now()
	if kind == domain.NotificationEmailVerification {
		t, err := l.verifications.GetByTokenHash(ctx, hash)
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return t.UsedAt == nil && now.Before(t.ExpiresAt), nil
	}
	t, err := l.resets.GetByTokenHash(ctx, hash)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil // replaced by a newer link
	}
	if err != nil {
		return false, err
	}
	return !t.Used && now.Before(t.ExpiresAt), nil
}

func (l emailLinks) Emailed(ctx context.Context, kind domain.NotificationKind, token, address string) error {
	if kind == domain.NotificationEmailVerification {
		return nil // bound to its address when it was made
	}
	return l.resets.MarkEmailed(ctx, service.HashResetToken(token), address)
}
