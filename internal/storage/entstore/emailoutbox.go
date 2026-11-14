package entstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/emailoutbox"
	"sso.internal/sso/ent/emailverificationtoken"
	"sso.internal/sso/ent/predicate"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entEmailOutboxRepository struct {
	client *ent.Client
}

func NewEmailOutboxRepository(client *ent.Client) repository.EmailOutboxRepository {
	return &entEmailOutboxRepository{client: client}
}

// maxErrorLen: what is kept of an SMTP error (column without limit, but a
// server can answer at length).
const maxErrorLen = 500

func (r *entEmailOutboxRepository) Create(ctx context.Context, e *domain.OutboxEmail) error {
	ev := e.Event
	ev.ResetToken = "" // never in clear: SealedToken
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("email outbox: encode event: %w", err)
	}
	status := e.Status
	if status == "" {
		status = domain.OutboxPending
	}
	b := r.client.EmailOutbox.Create().
		SetID(e.ID).
		SetRealmID(e.RealmID).
		SetUserID(e.UserID).
		SetKind(string(e.Kind)).
		SetEvent(string(raw)).
		SetStatus(entschema.EmailOutboxStatus(status)).
		SetAttempts(e.Attempts).
		SetNextAttemptAt(e.NextAttemptAt).
		SetDeadline(e.Deadline).
		SetNillableSealedToken(nonEmpty(e.SealedToken)).
		SetNillableLastError(nonEmpty(clip(e.LastError))).
		SetNillableRecipient(nonEmpty(e.Recipient)).
		SetNillableTemplate(nonEmpty(e.Template))
	if !e.CreatedAt.IsZero() {
		b.SetCreatedAt(e.CreatedAt)
	}
	_, err = b.Save(ctx)
	return err
}

// Claim is one statement:
//
//	UPDATE email_outbox SET claim = <mark>, locked_until = now+lease, attempts = attempts+1
//	WHERE id IN (SELECT id FROM email_outbox WHERE <pending, due, not held>
//	             ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED)
//
// then the row is read back by its mark. Two dispatchers never take the same
// row, and neither waits for the other.
func (r *entEmailOutboxRepository) Claim(ctx context.Context, id string, now time.Time, lease time.Duration) (*domain.OutboxEmail, error) {
	mark := uuid.NewString()
	n, err := r.client.EmailOutbox.Update().
		Where(predicate.EmailOutbox(func(s *sql.Selector) {
			t := sql.Table(emailoutbox.Table)
			conds := []*sql.Predicate{
				sql.EQ(t.C(emailoutbox.FieldStatus), string(entschema.EmailOutboxPending)),
				sql.LTE(t.C(emailoutbox.FieldNextAttemptAt), now),
				sql.Or(sql.IsNull(t.C(emailoutbox.FieldLockedUntil)), sql.LT(t.C(emailoutbox.FieldLockedUntil), now)),
			}
			if id != "" {
				conds = append(conds, sql.EQ(t.C(emailoutbox.FieldID), id))
			}
			sub := sql.Select(t.C(emailoutbox.FieldID)).From(t).Where(sql.And(conds...)).
				OrderBy(t.C(emailoutbox.FieldNextAttemptAt)).Limit(1).
				ForUpdate(sql.WithLockTables(emailoutbox.Table), sql.WithLockAction(sql.SkipLocked))
			s.Where(sql.In(s.C(emailoutbox.FieldID), sub))
		})).
		SetClaim(mark).
		SetLockedUntil(now.Add(lease)).
		AddAttempts(1).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, repository.ErrNotFound
	}
	e, err := r.client.EmailOutbox.Query().Where(emailoutbox.Claim(mark)).Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainOutboxEmail(e)
}

func (r *entEmailOutboxRepository) Sent(ctx context.Context, id, recipient, template string, at time.Time) error {
	return r.client.EmailOutbox.UpdateOneID(id).
		SetStatus(entschema.EmailOutboxSent).
		SetSentAt(at).
		SetRecipient(recipient).
		SetTemplate(template).
		ClearLastError().
		ClearLockedUntil().
		ClearClaim().
		Exec(ctx)
}

func (r *entEmailOutboxRepository) Retry(ctx context.Context, id string, next time.Time, lastError, recipient, template string) error {
	b := r.client.EmailOutbox.UpdateOneID(id).
		SetNextAttemptAt(next).
		SetLastError(clip(lastError)).
		ClearLockedUntil().
		ClearClaim()
	if recipient != "" {
		b.SetRecipient(recipient)
	}
	if template != "" {
		b.SetTemplate(template)
	}
	return b.Exec(ctx)
}

func (r *entEmailOutboxRepository) End(ctx context.Context, id string, status domain.OutboxStatus, reason, recipient, template string) error {
	b := r.client.EmailOutbox.UpdateOneID(id).
		SetStatus(entschema.EmailOutboxStatus(status)).
		SetLastError(clip(reason)).
		ClearLockedUntil().
		ClearClaim()
	if recipient != "" {
		b.SetRecipient(recipient)
	}
	if template != "" {
		b.SetTemplate(template)
	}
	return b.Exec(ctx)
}

func (r *entEmailOutboxRepository) Requeue(ctx context.Context, id string, now, deadline time.Time) (bool, error) {
	n, err := r.client.EmailOutbox.Update().
		Where(
			emailoutbox.ID(id),
			emailoutbox.StatusIn(entschema.EmailOutboxFailed, entschema.EmailOutboxPending),
			emailoutbox.Or(emailoutbox.LockedUntilIsNil(), emailoutbox.LockedUntilLT(now)),
		).
		SetStatus(entschema.EmailOutboxPending).
		SetAttempts(0).
		SetNextAttemptAt(now).
		SetDeadline(deadline).
		ClearLockedUntil().
		ClearClaim().
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *entEmailOutboxRepository) Get(ctx context.Context, id string) (*domain.OutboxEmail, error) {
	e, err := r.client.EmailOutbox.Get(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainOutboxEmail(e)
}

func (r *entEmailOutboxRepository) ListByUser(ctx context.Context, userID string, limit int) ([]*domain.OutboxEmail, error) {
	rows, err := r.client.EmailOutbox.Query().
		Where(emailoutbox.UserID(userID)).
		Order(ent.Desc(emailoutbox.FieldCreatedAt), ent.Desc(emailoutbox.FieldID)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return toDomainOutboxEmails(rows)
}

func (r *entEmailOutboxRepository) LatestByUsers(ctx context.Context, userIDs []string, kind domain.NotificationKind, since time.Time) (map[string]*domain.OutboxEmail, error) {
	out := make(map[string]*domain.OutboxEmail, len(userIDs))
	// In chunks: an import may have thousands of lines.
	for start := 0; start < len(userIDs); start += 1000 {
		chunk := userIDs[start:min(start+1000, len(userIDs))]
		rows, err := r.client.EmailOutbox.Query().
			Where(
				emailoutbox.UserIDIn(chunk...),
				emailoutbox.Kind(string(kind)),
				emailoutbox.CreatedAtGTE(since),
			).
			Order(ent.Asc(emailoutbox.FieldCreatedAt)).
			All(ctx)
		if err != nil {
			return nil, err
		}
		list, err := toDomainOutboxEmails(rows)
		if err != nil {
			return nil, err
		}
		for _, e := range list {
			out[e.UserID] = e // ascending: the latest wins
		}
	}
	return out, nil
}

func toDomainOutboxEmails(rows []*ent.EmailOutbox) ([]*domain.OutboxEmail, error) {
	out := make([]*domain.OutboxEmail, 0, len(rows))
	for _, e := range rows {
		d, err := toDomainOutboxEmail(e)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func toDomainOutboxEmail(e *ent.EmailOutbox) (*domain.OutboxEmail, error) {
	var ev domain.NotificationEvent
	if err := json.Unmarshal([]byte(e.Event), &ev); err != nil {
		return nil, fmt.Errorf("email outbox %s: decode event: %w", e.ID, err)
	}
	return &domain.OutboxEmail{
		ID:            e.ID,
		RealmID:       e.RealmID,
		UserID:        e.UserID,
		Kind:          domain.NotificationKind(e.Kind),
		Event:         ev,
		SealedToken:   e.SealedToken,
		Status:        domain.OutboxStatus(e.Status),
		Attempts:      e.Attempts,
		NextAttemptAt: e.NextAttemptAt,
		Deadline:      e.Deadline,
		LastError:     e.LastError,
		Recipient:     e.Recipient,
		Template:      e.Template,
		CreatedAt:     e.CreatedAt,
		UpdatedAt:     e.UpdatedAt,
		SentAt:        e.SentAt,
	}, nil
}

func clip(s string) string {
	// PostgreSQL refuses NUL and invalid UTF-8 in text: an error message
	// from a mail server is not trusted to be clean.
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "?")
	if len(s) <= maxErrorLen {
		return s
	}
	cut := maxErrorLen
	for cut > 0 && s[cut]&0xC0 == 0x80 { // not in the middle of a UTF-8 character
		cut--
	}
	return s[:cut] + "…"
}

// --- address verification links ------------------------------------------------

type entEmailVerificationRepository struct {
	client *ent.Client
}

func NewEmailVerificationRepository(client *ent.Client) repository.EmailVerificationRepository {
	return &entEmailVerificationRepository{client: client}
}

func (r *entEmailVerificationRepository) Create(ctx context.Context, t *domain.EmailVerificationToken) error {
	b := r.client.EmailVerificationToken.Create().
		SetUserID(t.UserID).
		SetEmail(domain.NormalizeIdentifier(t.Email)).
		SetTokenHash(t.TokenHash).
		SetExpiresAt(t.ExpiresAt)
	if t.ID != "" {
		b.SetID(t.ID)
	}
	if !t.CreatedAt.IsZero() {
		b.SetCreatedAt(t.CreatedAt)
	}
	e, err := b.Save(ctx)
	if err != nil {
		return err
	}
	t.ID, t.CreatedAt = e.ID, e.CreatedAt
	return nil
}

func (r *entEmailVerificationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.EmailVerificationToken, error) {
	e, err := r.client.EmailVerificationToken.Query().
		Where(emailverificationtoken.TokenHash(tokenHash)).
		Only(ctx)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &domain.EmailVerificationToken{
		ID: e.ID, UserID: e.UserID, Email: e.Email, TokenHash: e.TokenHash,
		ExpiresAt: e.ExpiresAt, UsedAt: e.UsedAt, CreatedAt: e.CreatedAt,
	}, nil
}

func (r *entEmailVerificationRepository) LatestCreatedAt(ctx context.Context, userID string) (time.Time, error) {
	e, err := r.client.EmailVerificationToken.Query().
		Where(emailverificationtoken.UserID(userID)).
		Order(ent.Desc(emailverificationtoken.FieldCreatedAt)).
		First(ctx)
	if ent.IsNotFound(err) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return e.CreatedAt, nil
}

func (r *entEmailVerificationRepository) Consume(ctx context.Context, id string, at time.Time) (bool, error) {
	n, err := r.client.EmailVerificationToken.Update().
		Where(emailverificationtoken.ID(id), emailverificationtoken.UsedAtIsNil()).
		SetUsedAt(at).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *entEmailVerificationRepository) DeleteUnusedByUser(ctx context.Context, userID string) (int, error) {
	return r.client.EmailVerificationToken.Delete().
		Where(emailverificationtoken.UserID(userID), emailverificationtoken.UsedAtIsNil()).
		Exec(ctx)
}

func (r *entEmailVerificationRepository) MarkEmailVerified(ctx context.Context, userID, email string, at time.Time) (bool, error) {
	n, err := r.client.User.Update().
		Where(user.ID(userID), user.Email(domain.NormalizeIdentifier(email)), user.EmailVerifiedAtIsNil()).
		SetEmailVerifiedAt(at).
		Save(ctx)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
