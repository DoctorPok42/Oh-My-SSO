package entstore

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/ent/emailoutbox"
	"sso.internal/sso/ent/emailverificationtoken"
	"sso.internal/sso/ent/knownaccount"
	"sso.internal/sso/ent/loginattempt"
	"sso.internal/sso/ent/passwordresettoken"
	"sso.internal/sso/ent/predicate"
	"sso.internal/sso/ent/realm"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/session"
	"sso.internal/sso/ent/token"
	"sso.internal/sso/ent/trusteddevice"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Every method is one statement:
//
//	DELETE FROM t WHERE id IN (SELECT id FROM t WHERE <ended> LIMIT n FOR UPDATE OF t SKIP LOCKED)
//
// so a server never waits for (nor deadlocks with) another one purging the
// same rows: each takes the rows nobody holds.
type entPurgeRepository struct {
	client *ent.Client
}

func NewPurgeRepository(client *ent.Client) repository.PurgeRepository {
	return &entPurgeRepository{client: client}
}

// batch is the predicate "id IN (up to limit unlocked rows of table that
// match where)". where adds its conditions (and joins) to the inner SELECT,
// whose table is t.
func batch(table string, limit int, where func(t *sql.SelectTable, s *sql.Selector)) func(*sql.Selector) {
	return func(s *sql.Selector) {
		t := sql.Table(table)
		sub := sql.Select(t.C("id")).From(t)
		where(t, sub)
		sub.Limit(limit).ForUpdate(sql.WithLockTables(table), sql.WithLockAction(sql.SkipLocked))
		s.Where(sql.In(s.C("id"), sub))
	}
}

func (r *entPurgeRepository) DeleteEndedSessions(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.Session.Delete().Where(predicate.Session(batch(session.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		s.Where(sql.And(
			sql.EQ(t.C(session.FieldRealmID), realmID),
			sql.Or(
				sql.LT(t.C(session.FieldExpiresAt), before),
				sql.And(
					sql.NEQ(t.C(session.FieldStatus), string(entschema.SessionActive)),
					sql.LT(t.C(session.FieldLastActivityAt), before),
				),
			),
		))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteExpiredTokens(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.Token.Delete().Where(predicate.Token(batch(token.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		sess := sql.Table(session.Table)
		s.Join(sess).On(t.C(token.FieldSessionID), sess.C(session.FieldID))
		s.Where(sql.And(
			sql.EQ(sess.C(session.FieldRealmID), realmID),
			sql.LT(t.C(token.FieldExpiresAt), before),
			sql.Or(
				sql.IsNull(t.C(token.FieldUsedAt)),
				sql.NEQ(sess.C(session.FieldStatus), string(entschema.SessionActive)),
			),
		))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteEndedResetLinks(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.PasswordResetToken.Delete().Where(predicate.PasswordResetToken(batch(passwordresettoken.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		users := sql.Table(user.Table)
		s.Where(sql.And(
			sql.In(t.C(passwordresettoken.FieldUserID),
				sql.Select(users.C(user.FieldID)).From(users).Where(sql.EQ(users.C(user.FieldRealmID), realmID))),
			sql.Or(
				sql.LT(t.C(passwordresettoken.FieldExpiresAt), before),
				// updated_at moves when the link is used.
				sql.And(sql.EQ(t.C(passwordresettoken.FieldUsed), true), sql.LT(t.C(passwordresettoken.FieldUpdatedAt), before)),
			),
		))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteEndedVerificationLinks(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.EmailVerificationToken.Delete().Where(predicate.EmailVerificationToken(batch(emailverificationtoken.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		users := sql.Table(user.Table)
		s.Where(sql.And(
			sql.In(t.C(emailverificationtoken.FieldUserID),
				sql.Select(users.C(user.FieldID)).From(users).Where(sql.EQ(users.C(user.FieldRealmID), realmID))),
			sql.Or(
				sql.LT(t.C(emailverificationtoken.FieldExpiresAt), before),
				sql.LT(t.C(emailverificationtoken.FieldUsedAt), before),
			),
		))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteEndedEmails(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.EmailOutbox.Delete().Where(predicate.EmailOutbox(batch(emailoutbox.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		s.Where(sql.And(
			sql.EQ(t.C(emailoutbox.FieldRealmID), realmID),
			sql.NEQ(t.C(emailoutbox.FieldStatus), string(entschema.EmailOutboxPending)),
			sql.LT(t.C(emailoutbox.FieldUpdatedAt), before),
		))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteLoginAttempts(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.LoginAttempt.Delete().Where(predicate.LoginAttempt(batch(loginattempt.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		inRealm := sql.EQ(t.C(loginattempt.FieldRealmID), realmID)
		if realmID == "" {
			realms := sql.Table(realm.Table)
			inRealm = sql.Or(
				sql.IsNull(t.C(loginattempt.FieldRealmID)),
				sql.NotIn(t.C(loginattempt.FieldRealmID), sql.Select(realms.C(realm.FieldID)).From(realms)),
			)
		}
		s.Where(sql.And(inRealm, sql.LT(t.C(loginattempt.FieldCreatedAt), before)))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteUnusedKnownAccounts(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.KnownAccount.Delete().Where(predicate.KnownAccount(batch(knownaccount.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		s.Where(sql.And(
			sql.EQ(t.C(knownaccount.FieldRealmID), realmID),
			sql.LT(t.C(knownaccount.FieldLastUsedAt), before),
		))
	}))).Exec(ctx)
}

func (r *entPurgeRepository) DeleteExpiredTrustedDevices(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.TrustedDevice.Delete().Where(predicate.TrustedDevice(batch(trusteddevice.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		s.Where(sql.And(
			sql.EQ(t.C(trusteddevice.FieldRealmID), realmID),
			sql.LT(t.C(trusteddevice.FieldExpiresAt), before),
		))
	}))).Exec(ctx)
}

// LastSuccessfulAuditEntry walks the index (realm_id, action, timestamp).
func (r *entPurgeRepository) LastSuccessfulAuditEntry(ctx context.Context, realmID, action string) (time.Time, error) {
	e, err := r.client.AuditLog.Query().
		Where(auditlog.RealmID(realmID), auditlog.Action(action),
			auditlog.StatusEQ(entschema.AuditLogStatus(domain.AuditLogSuccess))).
		Order(ent.Desc(auditlog.FieldTimestamp)).
		First(ctx)
	if ent.IsNotFound(err) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return e.Timestamp, nil
}

// DeleteAuditLogs walks the index (realm_id, timestamp).
func (r *entPurgeRepository) DeleteAuditLogs(ctx context.Context, realmID string, before time.Time, limit int) (int, error) {
	return r.client.AuditLog.Delete().Where(predicate.AuditLog(batch(auditlog.Table, limit, func(t *sql.SelectTable, s *sql.Selector) {
		s.Where(sql.And(
			sql.EQ(t.C(auditlog.FieldRealmID), realmID),
			sql.LT(t.C(auditlog.FieldTimestamp), before),
		))
	}))).Exec(ctx)
}
