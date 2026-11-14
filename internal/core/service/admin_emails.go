package service

import (
	"context"
	"errors"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// The e-mails of an account, as the console shows them (audit B-12), and
// the verification of its address (B-13).

// userEmailsShown: how many of an account's latest e-mails its drawer lists.
const userEmailsShown = 10

// OutboxEmailView is one e-mail of the outbox in the console. It never
// holds the link of the e-mail.
type OutboxEmailView struct {
	ID            string              `json:"id"`
	Kind          string              `json:"kind"`
	Status        domain.OutboxStatus `json:"status"`
	Attempts      int                 `json:"attempts"`
	Recipient     string              `json:"recipient,omitempty"`
	LastError     string              `json:"last_error,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	SentAt        *time.Time          `json:"sent_at"`
	NextAttemptAt *time.Time          `json:"next_attempt_at"` // pending only
	Deadline      time.Time           `json:"deadline"`
	// CanResend: "Send again" makes sense (failed or waiting, and its link,
	// if any, still has time).
	CanResend bool `json:"can_resend"`
}

func (s *AdminService) outboxView(e *domain.OutboxEmail, now time.Time) OutboxEmailView {
	v := OutboxEmailView{
		ID: e.ID, Kind: string(e.Kind), Status: e.Status, Attempts: e.Attempts, Recipient: e.Recipient,
		LastError: e.LastError, CreatedAt: e.CreatedAt, SentAt: e.SentAt, Deadline: e.Deadline,
	}
	if e.Status == domain.OutboxPending {
		t := e.NextAttemptAt
		v.NextAttemptAt = &t
	}
	v.CanResend = (e.Status == domain.OutboxFailed || e.Status == domain.OutboxPending) && !linkExpired(e, now)
	return v
}

// linkExpired: the e-mail carries a link that no longer works by date.
func linkExpired(e *domain.OutboxEmail, now time.Time) bool {
	return e.Kind.CarriesLink() && !e.Event.ExpiresAt.IsZero() && !now.Before(e.Event.ExpiresAt)
}

// userEmails lists an account's latest e-mails; nil without an outbox.
func (s *AdminService) userEmails(ctx context.Context, userID string) ([]OutboxEmailView, error) {
	out := []OutboxEmailView{}
	if s.d.Outbox == nil {
		return out, nil
	}
	rows, err := s.d.Outbox.ListByUser(ctx, userID, userEmailsShown)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	for _, e := range rows {
		out = append(out, s.outboxView(e, now))
	}
	return out, nil
}

// ResendEmail sends a failed (or still waiting) e-mail of an account again,
// at once, with 24 h more to get through. An e-mail whose link expired is
// refused: a new link is needed (new activation link, "forgot password").
func (s *AdminService) ResendEmail(ctx context.Context, actor AdminActor, realm *domain.Realm, userID, emailID string) (*UserDetail, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	if s.d.Outbox == nil {
		return nil, adminText(AdminRefused, "email_disabled", "", i18n.M("admin.error.email_disabled", "e-mail is not configured on the server (SMTP_HOST)"))
	}
	e, err := s.d.Outbox.Get(ctx, emailID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && e.UserID != u.ID) {
		return nil, adminText(AdminNotFound, "not_found", "", i18n.M("admin.error.email_not_found", "e-mail not found"))
	}
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	switch {
	case e.Status == domain.OutboxSent:
		return nil, adminText(AdminRefused, "email_sent", "", i18n.M("admin.error.email_already_sent", "this e-mail was sent"))
	case e.Status == domain.OutboxCancelled:
		return nil, adminText(AdminRefused, "email_cancelled", "", i18n.M("admin.error.email_cancelled", "this e-mail is no longer worth sending (its link was used or replaced, or the alert was switched off)"))
	case linkExpired(e, now):
		return nil, adminText(AdminRefused, "link_expired", "", i18n.M("admin.error.email_link_expired", "the link of this e-mail has expired: issue a new one"))
	}
	ok, err := s.d.Outbox.Requeue(ctx, e.ID, now, domain.OutboxDeadline(e.Event, now, domain.OutboxGiveUpAfter))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, adminText(AdminRefused, "email_sending", "", i18n.M("admin.error.email_sending", "this e-mail is being sent right now"))
	}
	if w, ok := s.d.Notifier.(interface{ Wake() }); ok {
		w.Wake()
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.NotificationRequeued, "User", u.ID, domain.AuditLogInfo, map[string]interface{}{
		"email_id": e.ID, "kind": string(e.Kind), "previous_status": string(e.Status), "attempts": e.Attempts,
	})
	return s.GetUser(ctx, realm, u.ID)
}

// SendEmailVerification e-mails the account a link that confirms its
// address.
func (s *AdminService) SendEmailVerification(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string) (*UserDetail, error) {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return nil, err
	}
	if s.d.EmailVerification == nil {
		return nil, adminText(AdminRefused, "email_disabled", "", i18n.M("admin.error.email_disabled", "e-mail is not configured on the server (SMTP_HOST)"))
	}
	expires, err := s.d.EmailVerification.Send(ctx, u, VerificationRequester{
		ActorType: domain.AuditActorAdmin, ActorID: actor.UserID, IPAddress: actor.IPAddress, UserAgent: actor.UserAgent, Silent: true,
	})
	switch {
	case errors.Is(err, ErrEmailAlreadyVerified):
		return nil, adminText(AdminRefused, "email_verified", "", i18n.M("admin.error.email_already_verified", "this address is already verified"))
	case errors.Is(err, ErrEmailVerificationTooSoon):
		return nil, adminText(AdminRefused, "too_soon", "", i18n.M("admin.error.email_verification_too_soon", "a verification e-mail was sent less than a minute ago"))
	case errors.Is(err, ErrEmailVerificationUnavailable):
		return nil, adminText(AdminRefused, "email_disabled", "", i18n.M("admin.error.email_verification_unavailable", "the verification e-mail cannot be sent (e-mail not configured, or the account is not active)"))
	case err != nil:
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.UserEmailVerificationSent, "User", u.ID, domain.AuditLogInfo, map[string]interface{}{
		"email": u.Email, "expires_at": expires.UTC().Format(time.RFC3339),
	})
	return s.GetUser(ctx, realm, u.ID)
}

// Delivery of the invitations of an import (UserImportRow.Delivery).
const (
	ImportDeliveryPending = "pending"
	ImportDeliverySent    = "sent"
	// ImportDeliveryFailed: failed, or cancelled before it left; the account
	// has not chosen its password (ResendFailedImportInvitations).
	ImportDeliveryFailed = "failed"
)

// importDeliveries fills Delivery on the rows of an import that e-mailed
// activation links, and counts the invitations that did not get through.
func (s *AdminService) importDeliveries(ctx context.Context, job *domain.UserImportJob, v *UserImportView) error {
	if s.d.Outbox == nil || !job.SendEmail || job.Status == domain.UserImportRunning {
		return nil
	}
	ids := []string{}
	for _, r := range v.Rows {
		if r.Status == domain.UserImportRowCreated && r.Emailed && r.UserID != "" {
			ids = append(ids, r.UserID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	latest, err := s.d.Outbox.LatestByUsers(ctx, ids, domain.NotificationAccountInvite, job.CreatedAt)
	if err != nil {
		return err
	}
	rows := make([]domain.UserImportRow, len(v.Rows)) // the job's rows stay as stored
	copy(rows, v.Rows)
	for i := range rows {
		e, ok := latest[rows[i].UserID]
		if !ok || !rows[i].Emailed {
			continue
		}
		switch e.Status {
		case domain.OutboxPending:
			rows[i].Delivery = ImportDeliveryPending
			v.EmailPending++
		case domain.OutboxSent:
			rows[i].Delivery = ImportDeliverySent
		default:
			rows[i].Delivery = ImportDeliveryFailed
			v.EmailFailed++
		}
	}
	v.Rows = rows
	return nil
}

// ResendFailedImportInvitations e-mails a new activation link to the
// accounts of an import whose invitation did not get through and that have
// not chosen a password since. It returns how many were sent.
func (s *AdminService) ResendFailedImportInvitations(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) (int, error) {
	job, err := s.userImportInRealm(ctx, realm.ID, id)
	if err != nil {
		return 0, err
	}
	if job.Status == domain.UserImportRunning {
		return 0, adminText(AdminRefused, "import_running", "", i18n.M("admin.error.import_resend_running", "the import is still running: its invitations can be sent again when it ends"))
	}
	if !s.d.EmailEnabled {
		return 0, adminText(AdminRefused, "email_disabled", "", i18n.M("admin.error.email_disabled", "e-mail is not configured on the server (SMTP_HOST)"))
	}
	v := userImportView(job)
	if err := s.importDeliveries(ctx, job, v); err != nil {
		return 0, err
	}
	sent := 0
	for _, row := range v.Rows {
		if row.Delivery != ImportDeliveryFailed {
			continue
		}
		u, err := s.userInRealm(ctx, realm.ID, row.UserID)
		if err != nil {
			if isAdminError(err) {
				continue // deleted since
			}
			return sent, err
		}
		if u.PasswordHash != "" {
			continue // activated since (another link)
		}
		res, err := s.issueActivationVia(ctx, actor, realm, u, true, true, s.notifyWait)
		if err != nil {
			return sent, err
		}
		if res.Emailed {
			sent++
		}
	}
	if sent > 0 {
		s.auditAdmin(ctx, actor, realm.ID, audit.UserActivationLinkSent, "UserImportJob", job.ID, domain.AuditLogInfo, map[string]interface{}{
			"emailed": true, "links": sent, "resent": true,
		})
	}
	return sent, nil
}
