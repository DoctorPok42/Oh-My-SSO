package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// The most items one bulk action may touch: the realm's bulk_limit
// (Settings), DefaultBulkLimit until it is changed. A selection larger than
// that is done in several passes, so a mistake stays small.
//
// A bulk action runs in the background, like a CSV import. The request that
// starts it checks everything the whole selection needs, records the job
// (bulk_jobs) and answers at once; the items are then done one after the
// other (the guardrails of an item read the state the previous one left), by
// the idp-admin process that received the request. The console follows the
// job by its id, from any idp-admin process: the state lives in the
// database.
//
// One bulk action runs per realm at a time. If the process stops cleanly
// (a deployment), the job ends as "interrupted" at the current item: it is
// finished once begun, the others are listed as not run, and the audit log
// gets a bulk.interrupted entry naming them. If the process dies, the reaper
// finds the job by its silence and does the same.
const (
	DefaultBulkLimit = 100
	MaxBulkLimit     = 500
)

const (
	// bulkCountEvery: how often a running bulk action saves its totals, what
	// the console's progress bar shows.
	bulkCountEvery = 200 * time.Millisecond
	// bulkFlushEvery: how often it also saves its items, which only matters
	// if the process dies.
	bulkFlushEvery = 2 * time.Second
	// bulkStaleAfter: a running job silent for this long lost its process.
	// Far above the time one item takes.
	bulkStaleAfter = 2 * time.Minute
	bulkReapEvery  = 30 * time.Second
	// bulkRetention: a report holds the names of what it touched. The audit
	// log keeps the trace.
	bulkRetention = 7 * 24 * time.Hour
	bulkFinishTTL = 30 * time.Second
)

// BulkLimit is the realm's bulk_limit, DefaultBulkLimit when it has no
// settings yet (or a value out of range).
func (s *AdminService) BulkLimit(ctx context.Context, realmID string) (int, error) {
	st, err := s.settingsOf(ctx, realmID)
	if err != nil {
		return 0, err
	}
	return effectiveBulkLimit(st), nil
}

func effectiveBulkLimit(st *domain.InstanceSettings) int {
	if st.BulkLimit < 1 || st.BulkLimit > MaxBulkLimit {
		return DefaultBulkLimit
	}
	return st.BulkLimit
}

// What became of one item of a bulk action.
const (
	BulkDone    = domain.BulkItemDone
	BulkSkipped = domain.BulkItemSkipped // a guardrail or nothing to do: the sentence says why
	BulkFailed  = domain.BulkItemFailed  // a server problem: logged, never shown
)

// The actions of POST /users/bulk.
const (
	BulkSuspend            = "suspend"
	BulkReactivate         = "reactivate"
	BulkUnlock             = "unlock"
	BulkForcePasswordReset = "force_password_reset"
	BulkResetMFA           = "reset_mfa"
	BulkAddGroup           = "add_group"
	BulkRemoveGroup        = "remove_group"
	BulkAddRole            = "add_role"
	BulkRemoveRole         = "remove_role"
	BulkResendInvite       = "resend_invite"
	BulkDelete             = "delete"
)

// The actions of POST /sessions/bulk.
const (
	BulkRevoke      = "revoke"       // ids of sessions
	BulkRevokeUsers = "revoke_users" // ids of users: all their sessions
)

// BulkInput is one bulk request.
type BulkInput struct {
	Action  string
	IDs     []string
	Reason  string // reset_mfa
	GroupID string // add_group, remove_group
	RoleID  string // add_role, remove_role
}

// BulkItem is the outcome of one item.
type BulkItem = domain.BulkItem

// BulkJobView is a bulk action as the console shows it: where it stands
// while it runs, its report once it is over (Items comes then). The audit
// entries of the items carry OperationID.
type BulkJobView struct {
	ID          string               `json:"id"`
	OperationID string               `json:"operation_id"`
	Action      string               `json:"action"`
	Status      domain.BulkJobStatus `json:"status"`
	Total       int                  `json:"total"`
	Processed   int                  `json:"processed"`
	Done        int                  `json:"done"`
	Skipped     int                  `json:"skipped"`
	Failed      int                  `json:"failed"`
	// NotRun: items the server stopped before (an interrupted job only).
	NotRun     int        `json:"not_run"`
	Items      []BulkItem `json:"items"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// bulkJobView: loc says, in the language of the reader, what became of the
// items the server did not (or could not tell it did) run.
func bulkJobView(j *domain.BulkJob, loc *i18n.Localizer) *BulkJobView {
	v := &BulkJobView{
		ID: j.ID, OperationID: j.OperationID, Action: j.Action, Status: j.Status,
		Total: j.Total, Processed: j.Processed, Done: j.Done, Skipped: j.Skipped, Failed: j.Failed,
		Items: []BulkItem{}, CreatedAt: j.CreatedAt, FinishedAt: j.FinishedAt,
	}
	if j.Status == domain.BulkJobRunning {
		return v
	}
	for _, it := range j.Items {
		switch it.Status {
		case domain.BulkItemNotRun:
			it.Code, it.Message = it.Status, loc.Text(i18n.M("admin.error.bulk_not_run", "not processed: the server stopped before this item"))
			v.NotRun++
		case domain.BulkItemUnknown:
			it.Code, it.Message = it.Status, loc.Text(i18n.M("admin.error.bulk_unknown", "the server stopped while working on this item: see the audit log of the operation"))
			v.NotRun++
		}
		v.Items = append(v.Items, it)
	}
	return v
}

// bulkOperation is the id of the running bulk action ("" outside one).
func bulkOperation(ctx context.Context) string {
	if b := audit.BatchOf(ctx); b != nil {
		return b.Operation()
	}
	return ""
}

func newBulkOperationID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("bulk: operation id: %w", err)
	}
	return "op_" + hex.EncodeToString(b), nil
}

// cleanBulkIDs drops empty and repeated ids, in order, and applies the
// realm's bulk limit.
func (s *AdminService) cleanBulkIDs(ctx context.Context, realm *domain.Realm, ids []string) ([]string, error) {
	limit, err := s.BulkLimit(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, adminInvalid("ids", i18n.M("admin.error.bulk_empty", "select at least one item"))
	}
	if len(out) > limit {
		return nil, adminText(AdminInvalid, "bulk_limit", "ids", i18n.M("admin.error.bulk_limit", "at most {limit} items at a time", "limit", limit))
	}
	return out, nil
}

func bulkUnknownAction() error {
	return adminInvalid("action", i18n.M("admin.error.bulk_action", "unknown bulk action"))
}

// bulkStep works on one item: it returns the name to show for it, even when
// it fails, and an error when the item was not changed.
type bulkStep func(ctx context.Context, id string) (label string, err error)

// runBulk records the job and starts it in the background: it answers with
// the job as it stands, the console follows it with GetBulkJob. The items
// are done one after the other: the guardrails read the current state, so a
// selection holding every administrator stops at the last one. The console
// hanging up does not stop it, and a server that stops finishes the current
// item, then ends the job as interrupted (see runBulkJob).
func (s *AdminService) runBulk(ctx context.Context, actor AdminActor, realm *domain.Realm, action string, ids []string, loc *i18n.Localizer, step bulkStep) (*BulkJobView, error) {
	op, err := newBulkOperationID()
	if err != nil {
		return nil, err
	}
	if !s.bulks.begin() {
		return nil, adminText(AdminRefused, "stopping", "", i18n.M("admin.error.bulk_stopping", "the server is stopping: start the action again in a moment"))
	}
	job, err := s.d.BulkJobs.Create(ctx, repository.CreateBulkJobParams{
		RealmID: realm.ID, Action: action, OperationID: op,
		RequestedBy: actor.UserID, RequestedByName: actor.Username, RequestedByRealm: actor.RealmID,
		IDs: ids,
	})
	if err != nil {
		s.bulks.wg.Done()
		if errors.Is(err, repository.ErrConflict) {
			return nil, adminText(AdminConflict, "bulk_running", "", i18n.M("admin.error.bulk_running", "another bulk action is running in this realm: wait for it to end"))
		}
		return nil, err
	}
	go s.runBulkJob(job, loc, step)
	return bulkJobView(job, loc), nil
}

// runBulkJob does the work of one job. It owns one s.bulks.wg slot.
//
// The items run on a context that ignores the server's stop (work): an item
// is finished once begun, so that nothing is left half done. The stop is
// looked at between two items only.
func (s *AdminService) runBulkJob(job *domain.BulkJob, loc *i18n.Localizer, step bulkStep) {
	defer s.bulks.wg.Done()
	stop := s.bulks.ctx
	// The audit entries of the items are gathered: the job writes one entry
	// at the end (finishBulkJob).
	batch := audit.NewBatch(job.OperationID)
	work := audit.WithBatch(context.WithoutCancel(stop), batch)

	p := repository.BulkJobProgress{Items: make([]BulkItem, 0, len(job.IDs))}
	status := domain.BulkJobInterrupted // until the last item is done
	defer func() { s.finishBulkJob(work, job, status, p, batch) }()

	counted, saved := s.d.Now(), s.d.Now()
	for _, id := range job.IDs {
		if stop.Err() != nil {
			return
		}
		batch.Item(id)
		item := s.bulkItemOf(work, id, loc, step)
		p.Processed++
		switch item.Status {
		case BulkDone:
			p.Done++
		case BulkSkipped:
			p.Skipped++
		default:
			p.Failed++
		}
		p.Items = append(p.Items, item)
		now := s.d.Now()
		if now.Sub(counted) < bulkCountEvery {
			continue
		}
		counted = now
		update := repository.BulkJobProgress{Processed: p.Processed, Done: p.Done, Skipped: p.Skipped, Failed: p.Failed}
		if now.Sub(saved) >= bulkFlushEvery {
			saved, update.Items = now, p.Items
		}
		if err := s.d.BulkJobs.UpdateProgress(work, job.ID, update); err != nil {
			s.d.Logger.WarnContext(work, "bulk action: progress not saved", "job_id", job.ID, "error", err)
		}
	}
	status = domain.BulkJobCompleted
}

// bulkItemOf does one item. A step that panics fails its item, not the job.
func (s *AdminService) bulkItemOf(ctx context.Context, id string, loc *i18n.Localizer, step bulkStep) BulkItem {
	var label string
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				s.d.Logger.ErrorContext(ctx, "bulk action: item panicked", "operation_id", bulkOperation(ctx), "item", id, "panic", r)
				err = fmt.Errorf("bulk item %s: panic: %v", id, r)
			}
		}()
		label, err = step(ctx, id)
	}()
	if label == "" {
		label = id
	}
	item := BulkItem{ID: id, Label: label, Status: BulkDone}
	var ae *AdminError
	switch {
	case err == nil:
	case errors.As(err, &ae):
		item.Status, item.Code, item.Message = BulkSkipped, ae.Code, s.bulkErrorText(ctx, err, loc)
	default:
		item.Status, item.Code, item.Message = BulkFailed, "internal_error", s.bulkErrorText(ctx, err, loc)
	}
	return item
}

// finishBulkJob saves the end of a job and writes its one audit entry. An
// interrupted one lists what it did not get to.
func (s *AdminService) finishBulkJob(ctx context.Context, job *domain.BulkJob, status domain.BulkJobStatus, p repository.BulkJobProgress, batch *audit.Batch) {
	changes := batch.Close() // from here on, entries are written as usual
	if status == domain.BulkJobInterrupted {
		p.Items = append(p.Items, bulkItemsLeft(job.IDs, len(p.Items), len(p.Items), domain.BulkItemNotRun)...)
	}
	ctx, cancel := context.WithTimeout(ctx, bulkFinishTTL)
	defer cancel()
	ok, err := s.d.BulkJobs.Finish(ctx, job.ID, status, p, s.d.Now())
	if err != nil {
		// The report is lost, the trace must not be.
		s.d.Logger.ErrorContext(ctx, "bulk action: end not saved", "job_id", job.ID, "error", err)
	} else if !ok {
		return // the reaper was first, and wrote the entry
	}
	job.Status, job.Processed, job.Done, job.Skipped, job.Failed, job.Items = status, p.Processed, p.Done, p.Skipped, p.Failed, p.Items
	s.auditBulkJob(ctx, job, changes)
}

// bulkItemsLeft lists ids[from:], as unknown up to ids[:unknownUntil], not run
// after: the outcomes a stopped job did not record.
func bulkItemsLeft(ids []string, from, unknownUntil int, status string) []BulkItem {
	if from >= len(ids) {
		return nil
	}
	out := make([]BulkItem, 0, len(ids)-from)
	for i := from; i < len(ids); i++ {
		st := status
		if i < unknownUntil {
			st = domain.BulkItemUnknown
		}
		out = append(out, BulkItem{ID: ids[i], Label: ids[i], Status: st})
	}
	return out
}

// bulkAuditItem is one item in the audit entry of a bulk action.
type bulkAuditItem struct {
	ID      string        `json:"id"`
	Label   string        `json:"label,omitempty"`
	Status  string        `json:"status"`
	Code    string        `json:"code,omitempty"`
	Changes []audit.Entry `json:"changes,omitempty"`
}

// auditBulkJob writes the one audit entry of a bulk action: bulk.completed,
// or bulk.interrupted when the server stopped before the end. It holds, item
// by item, the outcome and the changes made (changes: the entries the items
// would have written one by one; none when the process died, the outcomes
// saved in the report remain).
func (s *AdminService) auditBulkJob(ctx context.Context, job *domain.BulkJob, changes map[string][]audit.Entry) {
	action, level := audit.BulkCompleted, domain.AuditLogInfo
	if job.Status == domain.BulkJobInterrupted {
		action, level = audit.BulkInterrupted, domain.AuditLogWarning
	}
	if job.Failed > 0 {
		level = domain.AuditLogWarning
	}
	var left []string
	items := make([]bulkAuditItem, 0, len(job.Items))
	for _, it := range job.Items {
		if it.Status == domain.BulkItemNotRun || it.Status == domain.BulkItemUnknown {
			left = append(left, it.ID)
		}
		ai := bulkAuditItem{ID: it.ID, Status: it.Status, Code: it.Code, Changes: changes[it.ID]}
		if it.Label != it.ID {
			ai.Label = it.Label
		}
		for _, c := range ai.Changes {
			if c.Warning {
				level = domain.AuditLogWarning
			}
		}
		items = append(items, ai)
	}
	details := map[string]interface{}{
		"operation_id": job.OperationID, "bulk_action": job.Action, "total": job.Total, "processed": job.Processed,
		"done": job.Done, "skipped": job.Skipped, "failed": job.Failed,
		"items": items,
	}
	if job.Status == domain.BulkJobInterrupted {
		details["not_processed"], details["not_processed_ids"] = len(left), left
	}
	actor := AdminActor{UserID: job.RequestedBy, Username: job.RequestedByName, RealmID: job.RequestedByRealm}
	s.auditAdmin(ctx, actor, job.RealmID, action, "BulkJob", job.ID, level, details)
}

// StartBulkReaper ends the bulk actions whose process died, and purges old
// reports, until StopBulkJobs. Only idp-admin needs it.
func (s *AdminService) StartBulkReaper() {
	if !s.bulks.begin() {
		return
	}
	go func() {
		defer s.bulks.wg.Done()
		s.RunBulkReaper(s.bulks.ctx, bulkReapEvery)
	}()
}

// StopBulkJobs tells the running bulk actions to stop at their current item
// and waits for them, until ctx ends. A job still running then is found by
// the reaper of another process.
func (s *AdminService) StopBulkJobs(ctx context.Context) {
	if !s.bulks.stop(ctx) {
		s.d.Logger.Warn("bulk actions: stopped waiting for the running bulk actions")
	}
}

// RunBulkReaper checks every `every`, at once for the first time, until ctx
// ends.
func (s *AdminService) RunBulkReaper(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		s.reapBulkJobs(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *AdminService) reapBulkJobs(ctx context.Context) {
	now := s.d.Now()
	jobs, err := s.d.BulkJobs.ReapStale(ctx, now.Add(-bulkStaleAfter), now)
	if err != nil && ctx.Err() == nil {
		s.d.Logger.Warn("bulk actions: cannot look for lost bulk actions", "error", err)
	}
	for _, job := range jobs {
		s.d.Logger.Warn("bulk action: its process is gone, marked as interrupted",
			"job_id", job.ID, "operation_id", job.OperationID, "processed", job.Processed, "total", job.Total)
		// The items saved last may be behind the counts, and the one being
		// done when the process died is unknown: the audit log tells.
		saved := len(job.Items)
		job.Items = append(job.Items, bulkItemsLeft(job.IDs, saved, job.Processed+1, domain.BulkItemNotRun)...)
		if err := s.d.BulkJobs.SaveItems(ctx, job.ID, job.Items); err != nil {
			s.d.Logger.Warn("bulk action: report not saved", "job_id", job.ID, "error", err)
		}
		job.Status = domain.BulkJobInterrupted
		s.auditBulkJob(ctx, job, nil) // the changes of the items died with the process
	}
	if _, err := s.d.BulkJobs.DeleteFinishedBefore(ctx, now.Add(-bulkRetention)); err != nil && ctx.Err() == nil {
		s.d.Logger.Warn("bulk actions: cannot purge old reports", "error", err)
	}
}

// GetBulkJob returns where a bulk action stands, or its report. Only the
// administrator who started it reads it: the items name what it touched.
func (s *AdminService) GetBulkJob(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, loc *i18n.Localizer) (*BulkJobView, error) {
	job, err := s.d.BulkJobs.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) ||
		(err == nil && (job.RealmID != realm.ID || job.RequestedBy != actor.UserID || job.RequestedByRealm != actor.RealmID)) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.bulk_job", "bulk action not found"))
	}
	if err != nil {
		return nil, err
	}
	return bulkJobView(job, loc), nil
}

func (s *AdminService) bulkErrorText(ctx context.Context, err error, loc *i18n.Localizer) string {
	var ae *AdminError
	if errors.As(err, &ae) {
		if ae.Text.Key != "" {
			return loc.Text(ae.Text)
		}
		return ae.Message
	}
	s.d.Logger.ErrorContext(ctx, "bulk action: item failed", "operation_id", bulkOperation(ctx), "error", err)
	return loc.Text(i18n.M("admin.error.internal", "something went wrong on the server, see its logs"))
}

// userStep is an action on one user, already loaded.
type userStep func(ctx context.Context, u *domain.User) error

// BulkUsers runs one action on many users.
func (s *AdminService) BulkUsers(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkJobView, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	step, err := s.userBulkStep(ctx, actor, realm, in)
	if err != nil {
		return nil, err
	}
	return s.runBulk(ctx, actor, realm, in.Action, ids, loc, s.onUsers(actor, realm, step))
}

// onUsers loads each user and leaves out the administrator who asked: in
// the master realm, a bulk action could lock them out of the console.
func (s *AdminService) onUsers(actor AdminActor, realm *domain.Realm, step userStep) bulkStep {
	return func(ctx context.Context, id string) (string, error) {
		u, err := s.userInRealm(ctx, realm.ID, id)
		if err != nil {
			return "", err
		}
		if isMaster(realm) && u.ID == actor.UserID {
			return u.Username, adminRefused("self_change", i18n.M("admin.error.bulk_self", "your own account is left out of bulk actions"))
		}
		return u.Username, step(ctx, u)
	}
}

// userBulkStep checks what the whole request needs (a request that cannot
// work is refused, not skipped item by item) and chooses the action.
func (s *AdminService) userBulkStep(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput) (userStep, error) {
	switch in.Action {
	case BulkSuspend:
		return func(ctx context.Context, u *domain.User) error {
			if u.Status == domain.UserSuspended {
				return bulkSkip("already_suspended", i18n.M("admin.error.bulk_already_suspended", "already suspended"))
			}
			return s.setUserStatus(ctx, actor, realm, u, domain.UserSuspended)
		}, nil
	case BulkReactivate:
		return func(ctx context.Context, u *domain.User) error {
			if u.Status == domain.UserActive {
				return bulkSkip("already_active", i18n.M("admin.error.bulk_already_active", "already active"))
			}
			return s.setUserStatus(ctx, actor, realm, u, domain.UserActive)
		}, nil
	case BulkUnlock:
		return func(ctx context.Context, u *domain.User) error {
			if !u.Lockout.LockedAt(s.d.Now()) {
				return bulkSkip("not_locked", i18n.M("admin.error.bulk_not_locked", "not locked"))
			}
			return s.UnlockUser(ctx, actor, realm, u.ID)
		}, nil
	case BulkForcePasswordReset:
		return func(ctx context.Context, u *domain.User) error {
			return s.forcePasswordReset(ctx, actor, realm, u)
		}, nil
	case BulkResetMFA:
		reason := strings.TrimSpace(in.Reason)
		if reason == "" {
			return nil, adminInvalid("reason", i18n.M("admin.error.reason_required", "a reason is required (it goes to the audit log)"))
		}
		return func(ctx context.Context, u *domain.User) error {
			enrolled, err := s.d.Admin.UsersWithActiveMFA(ctx, []string{u.ID})
			if err != nil {
				return err
			}
			if !enrolled[u.ID] {
				return bulkSkip("no_mfa", i18n.M("admin.error.bulk_no_mfa", "no second factor enrolled"))
			}
			_, err = s.ResetUserMFA(ctx, actor, realm, u.ID, reason)
			return err
		}, nil
	case BulkAddGroup, BulkRemoveGroup:
		ids, err := s.checkGroupIDs(ctx, realm.ID, []string{in.GroupID})
		if err != nil {
			return nil, err
		}
		add := in.Action == BulkAddGroup
		return func(ctx context.Context, u *domain.User) error {
			m, err := s.d.Admin.Memberships(ctx, []string{u.ID})
			if err != nil {
				return err
			}
			next, err := toggleMembership(m[u.ID].GroupIDs, ids[0], add,
				bulkSkip("already_member", i18n.M("admin.error.bulk_already_member", "already in this group")),
				bulkSkip("not_member", i18n.M("admin.error.bulk_not_member", "not in this group")))
			if err != nil {
				return err
			}
			_, err = s.SetUserGroups(ctx, actor, realm, u.ID, next)
			return err
		}, nil
	case BulkAddRole, BulkRemoveRole:
		ids, err := s.checkRoleIDs(ctx, realm.ID, []string{in.RoleID})
		if err != nil {
			return nil, err
		}
		add := in.Action == BulkAddRole
		return func(ctx context.Context, u *domain.User) error {
			m, err := s.d.Admin.Memberships(ctx, []string{u.ID})
			if err != nil {
				return err
			}
			next, err := toggleMembership(m[u.ID].RoleIDs, ids[0], add,
				bulkSkip("already_assigned", i18n.M("admin.error.bulk_already_assigned", "already has this role")),
				bulkSkip("not_assigned", i18n.M("admin.error.bulk_not_assigned", "does not hold this role directly")))
			if err != nil {
				return err
			}
			_, err = s.SetUserRoles(ctx, actor, realm, u.ID, next)
			return err
		}, nil
	case BulkResendInvite:
		return func(ctx context.Context, u *domain.User) error {
			if !s.d.EmailEnabled {
				return bulkEmailDisabled()
			}
			res, err := s.ResendActivation(ctx, actor, realm, u.ID, true)
			if err != nil {
				return err
			}
			if !res.Emailed {
				// The link exists but nobody got it: a bulk answer never carries links.
				return bulkSkip("email_not_sent", i18n.M("admin.error.bulk_email_not_sent", "the e-mail could not be queued, try again"))
			}
			return nil
		}, nil
	case BulkDelete:
		return func(ctx context.Context, u *domain.User) error {
			return s.DeleteUser(ctx, actor, realm, u.ID)
		}, nil
	}
	return nil, bulkUnknownAction()
}

func bulkSkip(code string, t i18n.Text) error { return adminRefused(code, t) }

func bulkEmailDisabled() error {
	return bulkSkip("email_disabled", i18n.M("admin.error.bulk_email_disabled", "e-mail is not configured on this server"))
}

// toggleMembership is the new list of a user's groups or roles, or the given
// error when the action changes nothing.
func toggleMembership(current []string, id string, add bool, already, absent error) ([]string, error) {
	has := slices.Contains(current, id)
	switch {
	case add && has:
		return nil, already
	case !add && !has:
		return nil, absent
	case add:
		return append(slices.Clone(current), id), nil
	}
	return slices.DeleteFunc(slices.Clone(current), func(x string) bool { return x == id }), nil
}

func (s *AdminService) setUserStatus(ctx context.Context, actor AdminActor, realm *domain.Realm, u *domain.User, status domain.UserStatus) error {
	_, err := s.UpdateUser(ctx, actor, realm, u.ID, UpdateUserInput{Status: &status})
	return err
}

// forcePasswordReset: the user is signed out everywhere and gets a link by
// e-mail; signing in with the password is refused until it changes. Without
// e-mail nobody could get out of that state, so the user is skipped.
func (s *AdminService) forcePasswordReset(ctx context.Context, actor AdminActor, realm *domain.Realm, u *domain.User) error {
	switch {
	case !s.d.EmailEnabled:
		return bulkEmailDisabled()
	case u.Status != domain.UserActive:
		return bulkSkip("not_active", i18n.M("admin.error.bulk_not_active", "this account is not active"))
	case u.PasswordHash == "":
		return bulkSkip("no_password", i18n.M("admin.error.bulk_no_password", "this account has no password"))
	case u.MustChangePassword:
		return bulkSkip("already_required", i18n.M("admin.error.bulk_reset_already_required", "a new password is already required"))
	}
	if err := s.guardAdminRemoval(ctx, actor, realm, u.ID, i18n.M("admin.error.bulk_self", "your own account is left out of bulk actions")); err != nil {
		return err
	}
	// The link is created first but e-mailed last: whatever fails before,
	// the user never holds a link to an account that was not switched.
	link, err := s.d.PasswordReset.PrepareForcedResetLink(ctx, u, actor.IPAddress)
	if err != nil {
		return err
	}
	// undo puts the account back as it was, so that the admin can retry
	// (an account left flagged would be skipped as "already required").
	// It must run even when the request is cancelled.
	undo := func() {
		bg := context.WithoutCancel(ctx)
		notRequired := false
		if _, err := s.d.Users.Update(bg, u.ID, repository.UpdateUserParams{MustChangePassword: &notRequired}); err != nil {
			s.d.Logger.WarnContext(bg, "force password reset: cannot clear the flag", "user_id", u.ID, "error", err)
		}
		s.d.PasswordReset.CancelForcedResetLink(bg, u.ID)
	}
	// Flag before sign-out: nobody can sign in with the password in between.
	required := true
	if _, err := s.d.Users.Update(ctx, u.ID, repository.UpdateUserParams{MustChangePassword: &required}); err != nil {
		s.d.PasswordReset.CancelForcedResetLink(context.WithoutCancel(ctx), u.ID)
		return fmt.Errorf("force password reset: %w", err)
	}
	if err := s.d.Sessions.RevokeAllForUser(ctx, u.ID, domain.SessionRevokedAdminRevoked); err != nil {
		undo()
		return fmt.Errorf("force password reset: sign out: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.UserPasswordResetForced, "User", u.ID, domain.AuditLogWarning, nil)
	s.d.PasswordReset.SendForcedResetLink(ctx, link)
	return nil
}

// BulkSessions revokes sessions, chosen one by one or by user.
func (s *AdminService) BulkSessions(ctx context.Context, actor AdminActor, realm *domain.Realm, in BulkInput, loc *i18n.Localizer) (*BulkJobView, error) {
	ids, err := s.cleanBulkIDs(ctx, realm, in.IDs)
	if err != nil {
		return nil, err
	}
	switch in.Action {
	case BulkRevoke:
		return s.runBulk(ctx, actor, realm, in.Action, ids, loc, func(ctx context.Context, id string) (string, error) {
			return s.bulkRevokeSession(ctx, actor, realm, id)
		})
	case BulkRevokeUsers:
		return s.runBulk(ctx, actor, realm, in.Action, ids, loc, s.onUsers(actor, realm, func(ctx context.Context, u *domain.User) error {
			win, err := s.activeWindow(ctx, realm)
			if err != nil {
				return err
			}
			win.UserID = u.ID
			live, err := s.d.Admin.CountSessions(ctx, win)
			if err != nil {
				return err
			}
			if live == 0 {
				return bulkSkip("no_session", i18n.M("admin.error.bulk_no_session", "no active session"))
			}
			return s.RevokeUserSessions(ctx, actor, realm, u.ID)
		}))
	}
	return nil, bulkUnknownAction()
}

func (s *AdminService) bulkRevokeSession(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) (string, error) {
	label := ""
	if se, err := s.d.Sessions.GetActive(ctx, id); err == nil && se.RealmID == realm.ID {
		if u, err := s.d.Users.GetByID(ctx, se.UserID); err == nil {
			label = u.Username
		}
	}
	if id == actor.SessionID {
		return label, bulkSkip("own_session", i18n.M("admin.error.bulk_own_session", "your own session is left out of bulk actions"))
	}
	return label, s.RevokeSession(ctx, actor, realm, id)
}
