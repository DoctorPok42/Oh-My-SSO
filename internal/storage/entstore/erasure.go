package entstore

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/ent/bulkjob"
	"sso.internal/sso/ent/loginattempt"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/user"
	"sso.internal/sso/ent/userimportjob"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

type entErasureRepository struct {
	client *ent.Client
}

func NewErasureRepository(client *ent.Client) repository.ErasureRepository {
	return &entErasureRepository{client: client}
}

func (r *entErasureRepository) ScheduleDeletion(ctx context.Context, userID string, at *time.Time) error {
	u := r.client.User.UpdateOneID(userID)
	if at == nil {
		u.ClearDeletionScheduledAt()
	} else {
		u.SetDeletionScheduledAt(*at)
	}
	return mapNotFound(u.Exec(ctx))
}

func (r *entErasureRepository) DeletionDue(ctx context.Context, before time.Time, limit int) ([]*domain.User, error) {
	rows, err := r.client.User.Query().
		Where(user.DeletionScheduledAtLT(before)).
		Order(ent.Asc(user.FieldDeletionScheduledAt)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.User, 0, len(rows))
	for _, e := range rows {
		out = append(out, toDomainUser(e))
	}
	return out, nil
}

// errNotErased rolls back the traces of an account that was not deleted.
var errNotErased = errors.New("entstore: account gone or no longer due")

func (r *entErasureRepository) EraseAccount(ctx context.Context, u *domain.User, dueBy *time.Time) (bool, error) {
	err := withTx(ctx, r.client, func(tx *ent.Tx) error {
		if err := eraseTraces(ctx, tx, u); err != nil {
			return err
		}
		// Last, so that a cancel committed meanwhile is seen (the row is
		// read again under its lock) and undoes the traces above with it.
		del := tx.User.Delete().Where(user.ID(u.ID))
		if dueBy != nil {
			del = del.Where(user.DeletionScheduledAtLTE(*dueBy))
		}
		n, err := del.Exec(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return errNotErased
		}
		return nil
	})
	if errors.Is(err, errNotErased) {
		return false, nil
	}
	return err == nil, err
}

func eraseTraces(ctx context.Context, tx *ent.Tx, u *domain.User) error {
	e := newEraser(u)
	for _, step := range []func(context.Context, *ent.Tx, *domain.User, *eraser) error{
		deleteSignInAttempts, eraseAuditTraces, eraseBulkReports, eraseImportReports,
	} {
		if err := step(ctx, tx, u, e); err != nil {
			return err
		}
	}
	return nil
}

// deleteSignInAttempts: by account, and the names typed on the sign-in page
// of its realm (an unknown-account attempt has no user_id).
func deleteSignInAttempts(ctx context.Context, tx *ent.Tx, u *domain.User, e *eraser) error {
	_, err := tx.LoginAttempt.Delete().Where(loginattempt.Or(
		loginattempt.UserID(u.ID),
		loginattempt.And(loginattempt.RealmID(u.RealmID), predicateLower(loginattempt.FieldIdentifier, e.names)),
	)).Exec(ctx)
	return err
}

func eraseAuditTraces(ctx context.Context, tx *ent.Tx, u *domain.User, e *eraser) error {
	// Where the entries came from, when it was this person's browser: what
	// they did, and what was done with their name without an administrator
	// (a failed sign-in, a lockout). An administrator's address stays on
	// what the administrator did.
	if _, err := tx.AuditLog.Update().Where(auditlog.Or(
		auditlog.UserID(u.ID),
		auditlog.And(auditlog.TargetUserID(u.ID), auditlog.ActorTypeIn(
			entschema.AuditActorUser, entschema.AuditActorAnonymous, entschema.AuditActorSystem)),
	)).ClearIPAddress().ClearUserAgent().Save(ctx); err != nil {
		return err
	}

	entries, err := tx.AuditLog.Query().Where(
		auditlog.DetailsNotNil(),
		auditlog.Or(
			// About it, with a name or an address it no longer has, or
			// asked for and never got: nothing current names it there.
			auditlog.And(
				auditlog.TargetUserID(u.ID),
				predicateJSONHasKey(auditlog.FieldDetails, slices.Sorted(maps.Keys(ownKeys))),
			),
			auditlog.And(
				auditlog.Or(auditlog.UserID(u.ID), auditlog.TargetUserID(u.ID), auditlog.RealmID(u.RealmID)),
				predicateJSONMentions(auditlog.FieldDetails, e.needles()),
			),
		),
	).All(ctx)
	if err != nil {
		return err
	}
	for _, a := range entries {
		// Only what targets the account: an entry it wrote about nobody (an
		// import) holds other people's names, which stay. Its own names are
		// still found there by value (isName).
		d, changed := e.scrub(a.Details, a.TargetUserID == u.ID, "")
		if !changed {
			continue
		}
		if err := tx.AuditLog.UpdateOneID(a.ID).SetDetails(d.(map[string]interface{})).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// eraseBulkReports: its name as the requester, its label as an item.
func eraseBulkReports(ctx context.Context, tx *ent.Tx, u *domain.User, _ *eraser) error {
	jobs, err := tx.BulkJob.Query().Where(bulkjob.Or(
		bulkjob.RequestedBy(u.ID),
		bulkjob.And(bulkjob.RealmID(u.RealmID), predicateJSONMentions(bulkjob.FieldItems, []string{u.ID})),
	)).All(ctx)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		upd, changed := tx.BulkJob.UpdateOneID(j.ID), j.RequestedBy == u.ID
		if changed {
			upd.SetRequestedByName(repository.Erased)
		}
		for i := range j.Items {
			if j.Items[i].ID == u.ID {
				j.Items[i].Label, changed = repository.Erased, true
			}
		}
		if !changed {
			continue
		}
		if err := upd.SetItems(j.Items).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// eraseImportReports: its name as the requester, its row as an account
// created (by id, or by address for a row that failed).
func eraseImportReports(ctx context.Context, tx *ent.Tx, u *domain.User, e *eraser) error {
	imports, err := tx.UserImportJob.Query().Where(userimportjob.Or(
		userimportjob.RequestedBy(u.ID),
		userimportjob.And(userimportjob.RealmID(u.RealmID), predicateJSONMentions(userimportjob.FieldRows, e.needles())),
	)).All(ctx)
	if err != nil {
		return err
	}
	for _, j := range imports {
		upd, changed := tx.UserImportJob.UpdateOneID(j.ID), j.RequestedBy == u.ID
		if changed {
			upd.SetRequestedByName(repository.Erased)
		}
		for i := range j.Rows {
			row := &j.Rows[i]
			if row.UserID == u.ID || e.isEmail(row.Email) {
				row.Email, row.Username, changed = repository.Erased, repository.Erased, true
			}
		}
		if !changed {
			continue
		}
		if err := upd.SetRows(j.Rows).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// eraser finds the account's username and e-mail address in JSON values.
type eraser struct {
	id, username, email string
	names               []string // lower case, non-empty
	emailRe             *regexp.Regexp
}

func newEraser(u *domain.User) *eraser {
	e := &eraser{id: u.ID, username: strings.TrimSpace(u.Username), email: strings.TrimSpace(u.Email)}
	for _, n := range []string{e.username, e.email} {
		if n != "" {
			e.names = append(e.names, strings.ToLower(n))
		}
	}
	if e.email != "" {
		e.emailRe = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(e.email))
	}
	return e
}

func (e *eraser) needles() []string { return append([]string{e.id}, e.names...) }

func (e *eraser) isName(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && (strings.EqualFold(s, e.username) || strings.EqualFold(s, e.email))
}

func (e *eraser) isEmail(s string) bool {
	return e.email != "" && strings.EqualFold(strings.TrimSpace(s), e.email)
}

// identityKeys hold a person's name wherever they appear.
var identityKeys = map[string]bool{"username": true, "admin_username": true, "identifier": true, "login_hint": true}

// ownKeys, in an entry about the account, hold one of its own names or
// addresses: the current ones, or ones it had or asked for (a rename, an
// e-mail change, the recipient of an e-mail), which the eraser cannot
// recognise by value. Never "admin_username": there, the administrator's.
var ownKeys = map[string]bool{"username": true, "identifier": true, "email": true, "to": true, "label": true}

// owned: s names the account. In an entry about it, any value under ownKeys
// or equal to its names; elsewhere, its username under identityKeys only (a
// word equal to a username elsewhere is not that person).
func (e *eraser) owned(s string, about bool, key string) bool {
	if s == "" || s == repository.Erased {
		return false
	}
	if about && ownKeys[key] {
		return true
	}
	return (about || identityKeys[key]) && e.isName(s)
}

// scrub replaces the account's names in v (owned), and its e-mail address
// wherever it appears. about: v is about the account; an object {"id":
// <account>, ...} is about the account.
func (e *eraser) scrub(v any, about bool, key string) (any, bool) {
	switch x := v.(type) {
	case string:
		return e.scrubString(x, about, key)
	case map[string]interface{}:
		return e.scrubObject(x, about)
	case []interface{}:
		changed := false
		for i, val := range x {
			if nv, ok := e.scrub(val, about, key); ok {
				x[i], changed = nv, true
			}
		}
		return x, changed
	}
	return v, false
}

func (e *eraser) scrubString(s string, about bool, key string) (any, bool) {
	if e.owned(s, about, key) {
		return repository.Erased, true
	}
	if e.emailRe != nil && e.emailRe.MatchString(s) {
		return e.emailRe.ReplaceAllLiteralString(s, repository.Erased), true
	}
	return s, false
}

// scrubObject: an object with the account's id is about it.
func (e *eraser) scrubObject(m map[string]interface{}, about bool) (any, bool) {
	inner := about || m["id"] == e.id || m["user_id"] == e.id
	changed := false
	for k, val := range m {
		if nv, ok := e.scrub(val, inner, k); ok {
			m[k], changed = nv, true
		}
	}
	return m, changed
}

// predicateLower: LOWER(column) is one of values (lower case already).
func predicateLower(column string, values []string) func(*sql.Selector) {
	return func(s *sql.Selector) {
		if len(values) == 0 {
			s.Where(sql.False())
			return
		}
		args := make([]any, len(values))
		for i, v := range values {
			args[i] = v
		}
		s.Where(sql.In(sql.Lower(s.C(column)), args...))
	}
}

// predicateJSONMentions: the JSON column, read as text, contains one of
// needles (case-insensitive). A superset of the rows to change: the caller
// checks the values themselves.
func predicateJSONMentions(column string, needles []string) func(*sql.Selector) {
	return func(s *sql.Selector) {
		var ps []*sql.Predicate
		for _, n := range needles {
			if n == "" {
				continue
			}
			pattern := "%" + n + "%"
			ps = append(ps, sql.P(func(b *sql.Builder) {
				b.WriteString("CAST(").WriteString(s.C(column)).WriteString(" AS text) ILIKE ").Arg(pattern)
			}))
		}
		if len(ps) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.Or(ps...))
	}
}

// predicateJSONHasKey: the JSON column has one of keys at its top level.
func predicateJSONHasKey(column string, keys []string) func(*sql.Selector) {
	return func(s *sql.Selector) {
		ps := make([]*sql.Predicate, len(keys))
		for i, k := range keys {
			ps[i] = sqljson.HasKey(s.C(column), sqljson.Path(k))
		}
		s.Where(sql.Or(ps...))
	}
}
