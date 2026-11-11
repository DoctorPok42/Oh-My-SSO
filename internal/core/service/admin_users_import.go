package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// Importing users from a CSV file (admin_users_csv.go), in two steps:
//
//	preview  every line is checked, nothing is written; the console shows
//	         the result before anything happens.
//	import   the lines are created one by one in the background, by the
//	         idp-admin process that received the file. The same checks run
//	         again: the realm may have changed since the preview. A refused
//	         line does not stop the others.
//
// An import only ever creates accounts: a line about an account that exists
// is refused, never merged. The audit log gets one entry when it starts and
// one when it ends, not three per account: a file of a hundred people would
// bury everything else. The last entry lists each account created with its
// groups and roles, so nothing an invitation records is lost. An e-mail that
// fails is the exception: it keeps its own entry.
//
// The state lives in the database (user_import_jobs), so any console can
// follow it. If the process stops cleanly, the import ends as "interrupted"
// at the current line. If it dies, the reaper finds the job by its silence.
// Either way, importing the same file again finishes the work: the lines
// already done are refused as already existing.
const (
	// userImportCountEvery: how often a running import saves its totals, what
	// the console's progress bar shows. Often enough for a file that takes a
	// second: an import does about 80 lines per second.
	userImportCountEvery = 200 * time.Millisecond
	// userImportFlushEvery: how often it also saves its report, which only
	// matters if the process dies: that one can weigh 150 KB.
	userImportFlushEvery = 2 * time.Second
	// userImportStaleAfter: a running import silent for this long lost its
	// process. Far above userImportFlushEvery: one line can wait a while for
	// room in the e-mail queue when the mail server is slow.
	userImportStaleAfter = 10 * time.Minute
	userImportReapEvery  = time.Minute
	// userImportRetention: a report holds addresses; it does not stay forever.
	userImportRetention = 30 * 24 * time.Hour
	userImportFinishTTL = 30 * time.Second
	userImportListSize  = 10
	maxImportFileName   = 200
)

// QueueNotifier is a Notifier that can wait for room in its queue. Notify
// drops an event when the queue is full: right for a single e-mail, not for
// a thousand invitations in a row.
type QueueNotifier interface {
	NotifyWait(ctx context.Context, e domain.NotificationEvent) error
}

// notifyWait queues an event, waiting if the notifier can.
func (s *AdminService) notifyWait(ctx context.Context, e domain.NotificationEvent) error {
	if q, ok := s.d.Notifier.(QueueNotifier); ok {
		return q.NotifyWait(ctx, e)
	}
	s.d.Notifier.Notify(ctx, e)
	return nil
}

// jobRunner tracks the goroutines of background jobs (the imports, the bulk
// actions), so that a stopping server can end them before it closes the
// database.
type jobRunner struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
}

func newJobRunner() *jobRunner {
	ctx, cancel := context.WithCancel(context.Background())
	return &jobRunner{ctx: ctx, cancel: cancel}
}

// begin registers a goroutine. false: the server is stopping.
func (r *jobRunner) begin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false
	}
	r.wg.Add(1)
	return true
}

// stop refuses new goroutines, tells the running ones to stop at their next
// item, and waits for them until ctx ends. false: ctx ended first.
func (r *jobRunner) stop(ctx context.Context) bool {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	r.cancel()

	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// StartUserImportReaper ends the imports whose process died, and purges old
// reports, until StopUserImports. Only idp-admin needs it.
func (s *AdminService) StartUserImportReaper() {
	if !s.imports.begin() {
		return
	}
	go func() {
		defer s.imports.wg.Done()
		s.RunUserImportReaper(s.imports.ctx, userImportReapEvery)
	}()
}

// StopUserImports interrupts the running imports at their current line and
// waits for them, until ctx ends.
func (s *AdminService) StopUserImports(ctx context.Context) {
	if !s.imports.stop(ctx) {
		s.d.Logger.Warn("user imports: stopped waiting for the running imports")
	}
}

// UserImportRowValid: the outcome of a line in a preview.
const UserImportRowValid = "valid"

// UserImportPreview is what a file would do.
type UserImportPreview struct {
	Total          int                    `json:"total"`
	Valid          int                    `json:"valid"`
	Invalid        int                    `json:"invalid"`
	ProfileColumns []string               `json:"profile_columns"`
	IgnoredColumns []string               `json:"ignored_columns"`
	Rows           []domain.UserImportRow `json:"rows"`
	// EmailEnabled: invitations can leave this server.
	EmailEnabled bool `json:"email_enabled"`
}

// PreviewUserImport checks every line of a file and writes nothing. loc is
// the language of the report (nil: English).
func (s *AdminService) PreviewUserImport(ctx context.Context, realm *domain.Realm, data string, loc *i18n.Localizer) (*UserImportPreview, error) {
	file, err := parseUserCSV(data)
	if err != nil {
		return nil, err
	}
	v, err := s.newImportChecker(ctx, realm)
	if err != nil {
		return nil, err
	}
	out := &UserImportPreview{
		Total: len(file.rows), ProfileColumns: orEmpty(file.profileColumns), IgnoredColumns: orEmpty(file.ignoredColumns),
		Rows: make([]domain.UserImportRow, 0, len(file.rows)), EmailEnabled: s.d.EmailEnabled,
	}
	for i := range file.rows {
		row := baseImportRow(&file.rows[i])
		p, err := v.check(ctx, &file.rows[i])
		switch {
		case err != nil && !isAdminError(err):
			return nil, err // the database, not the line
		case err != nil:
			row.Status, row.Error = domain.UserImportRowFailed, s.importErrorText(ctx, err, loc)
			out.Invalid++
		default:
			row.Status, row.Email, row.Username = UserImportRowValid, p.email, p.username
			out.Valid++
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// StartUserImportInput: what the console sends.
type StartUserImportInput struct {
	CSV      string
	FileName string
	// SendEmail: e-mail each new account its activation link. Otherwise the
	// accounts wait, and UserImportActivationLinks makes the links.
	SendEmail bool
	// NotifyWhenDone: e-mail the administrator at the end.
	NotifyWhenDone bool
	// Language of the report (nil: English).
	Localizer *i18n.Localizer
}

// StartUserImport reads the file and starts the import in the background.
// A file that cannot be read is refused here; a line that is wrong ends up
// in the report.
func (s *AdminService) StartUserImport(ctx context.Context, actor AdminActor, realm *domain.Realm, in StartUserImportInput) (*UserImportView, error) {
	file, err := parseUserCSV(in.CSV)
	if err != nil {
		return nil, err
	}
	if !s.imports.begin() {
		return nil, adminText(AdminRefused, "stopping", "", i18n.M("admin.error.import_stopping", "the server is stopping: start the import again in a moment"))
	}
	job, err := s.d.UserImports.Create(ctx, repository.CreateUserImportParams{
		RealmID: realm.ID, FileName: cleanImportFileName(in.FileName),
		RequestedBy: actor.UserID, RequestedByName: actor.Username, RequestedByRealm: actor.RealmID,
		SendEmail: in.SendEmail && s.d.EmailEnabled, NotifyWhenDone: in.NotifyWhenDone && s.d.EmailEnabled,
		Total: len(file.rows), IgnoredColumns: file.ignoredColumns,
	})
	if err != nil {
		s.imports.wg.Done()
		if errors.Is(err, repository.ErrConflict) {
			return nil, adminText(AdminConflict, "import_running", "", i18n.M("admin.error.import_running", "an import is already running in this realm: wait for it to end"))
		}
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.UserImportStarted, "UserImportJob", job.ID, domain.AuditLogInfo, map[string]interface{}{
		"file": job.FileName, "total": job.Total, "send_email": job.SendEmail, "ignored_columns": job.IgnoredColumns,
	})
	go s.runUserImport(job, actor, realm, file.rows, in.Localizer)
	return userImportView(job), nil
}

// runUserImport does the work of one import. It owns one s.imports.wg slot.
//
// The lines run on a context that ignores the server's stop (work): a line
// is finished once begun, so that no account is left half made. Only the
// wait for the e-mail queue follows the stop, because that one can be long.
func (s *AdminService) runUserImport(job *domain.UserImportJob, actor AdminActor, realm *domain.Realm, rows []importRow, loc *i18n.Localizer) {
	defer s.imports.wg.Done()
	stop := s.imports.ctx
	work := context.WithoutCancel(stop)

	progress := repository.UserImportProgress{Rows: make([]domain.UserImportRow, 0, len(rows))}
	status := domain.UserImportInterrupted // until the last line is done
	defer func() {
		if r := recover(); r != nil {
			s.d.Logger.Error("user import: panic", "job_id", job.ID, "panic", r)
		}
		s.finishUserImport(work, job, realm.Name, status, progress)
	}()

	checker, err := s.newImportChecker(work, realm)
	if err != nil {
		s.d.Logger.Error("user import: cannot read the realm", "job_id", job.ID, "error", err)
		return
	}
	counted, saved := s.d.Now(), s.d.Now()
	for i := range rows {
		if stop.Err() != nil {
			return
		}
		out := s.importUserRow(work, stop, actor, realm, checker, &rows[i], job.SendEmail, loc)
		progress.Processed++
		if out.Status == domain.UserImportRowCreated {
			progress.Created++
		} else {
			progress.Failed++
		}
		progress.Rows = append(progress.Rows, out)
		now := s.d.Now()
		if now.Sub(counted) < userImportCountEvery {
			continue
		}
		counted = now
		update := repository.UserImportProgress{Processed: progress.Processed, Created: progress.Created, Failed: progress.Failed}
		if now.Sub(saved) >= userImportFlushEvery {
			saved, update.Rows = now, progress.Rows
		}
		if err := s.d.UserImports.UpdateProgress(work, job.ID, update); err != nil {
			s.d.Logger.Warn("user import: progress not saved", "job_id", job.ID, "error", err)
		}
	}
	status = domain.UserImportCompleted
}

func (s *AdminService) importUserRow(ctx, stop context.Context, actor AdminActor, realm *domain.Realm, checker *importChecker,
	row *importRow, sendEmail bool, loc *i18n.Localizer) domain.UserImportRow {
	out := baseImportRow(row)
	refuse := func(err error) domain.UserImportRow {
		out.Status, out.Error = domain.UserImportRowFailed, s.importErrorText(ctx, err, loc)
		return out
	}
	p, err := checker.check(ctx, row)
	if err != nil {
		return refuse(err)
	}
	out.Email, out.Username = p.email, p.username
	u, err := s.createAccount(ctx, realm, p)
	if err != nil {
		return refuse(err)
	}
	out.Status, out.UserID, out.Groups, out.Roles = domain.UserImportRowCreated, u.ID, row.groups, row.roles
	if !sendEmail {
		return out
	}
	res, err := s.issueActivationVia(ctx, actor, realm, u, true, true, func(_ context.Context, e domain.NotificationEvent) error {
		return s.notifyWait(stop, e) // waits for the mail server, not for the database
	})
	if err != nil {
		// The account exists: UserImportActivationLinks can still reach it.
		s.d.Logger.Warn("user import: no activation link", "user_id", u.ID, "error", err)
		return out
	}
	out.Emailed = res.Emailed
	return out
}

func (s *AdminService) finishUserImport(ctx context.Context, job *domain.UserImportJob, realmName string, status domain.UserImportStatus, p repository.UserImportProgress) {
	ctx, cancel := context.WithTimeout(ctx, userImportFinishTTL)
	defer cancel()
	ok, err := s.d.UserImports.Finish(ctx, job.ID, status, p, s.d.Now())
	if err != nil {
		s.d.Logger.Error("user import: end not saved", "job_id", job.ID, "error", err)
		return
	}
	if !ok {
		return // the reaper was first, and told the administrator
	}
	job.Status, job.Processed, job.Created, job.Failed, job.Rows = status, p.Processed, p.Created, p.Failed, p.Rows
	s.announceUserImport(ctx, job, realmName)
}

// announceUserImport writes the end of an import to the audit log and, if
// asked, tells the administrator who started it.
func (s *AdminService) announceUserImport(ctx context.Context, job *domain.UserImportJob, realmName string) {
	interrupted := job.Status == domain.UserImportInterrupted
	level := domain.AuditLogInfo
	if interrupted || job.Failed > 0 {
		level = domain.AuditLogWarning
	}
	actor := AdminActor{UserID: job.RequestedBy, Username: job.RequestedByName, RealmID: job.RequestedByRealm}
	s.auditAdmin(ctx, actor, job.RealmID, audit.UserImportFinished, "UserImportJob", job.ID, level, map[string]interface{}{
		"file": job.FileName, "status": string(job.Status), "total": job.Total, "created": job.Created, "failed": job.Failed,
		"created_users": importedUsers(job.Rows),
	})
	if !job.NotifyWhenDone {
		return
	}
	err := s.notifyWait(ctx, domain.NotificationEvent{
		Kind: domain.NotificationUserImportFinished, RealmID: job.RequestedByRealm, UserID: job.RequestedBy,
		OccurredAt: s.d.Now(), ImportRealm: realmName, ImportFile: job.FileName,
		ImportTotal: job.Total, ImportCreated: job.Created, ImportFailed: job.Failed,
		ImportInterrupted: interrupted, ImportURL: s.userImportURL(realmName, job.ID),
	})
	if err != nil {
		s.d.Logger.Warn("user import: end not e-mailed", "job_id", job.ID, "error", err)
	}
}

// importedUsers: what the audit log keeps of the accounts of an import, the
// report being purged after userImportRetention.
func importedUsers(rows []domain.UserImportRow) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.Status != domain.UserImportRowCreated {
			continue
		}
		u := map[string]interface{}{"username": r.Username, "email": r.Email}
		if len(r.Groups) > 0 {
			u["groups"] = r.Groups
		}
		if len(r.Roles) > 0 {
			u["roles"] = r.Roles
		}
		out = append(out, u)
	}
	return out
}

func (s *AdminService) userImportURL(realmName, jobID string) string {
	if s.d.ConsoleURL == "" {
		return ""
	}
	return s.d.ConsoleURL + "/r/" + url.PathEscape(realmName) + "/users?import=" + url.QueryEscape(jobID)
}

// RunUserImportReaper checks every `every`, at once for the first time,
// until ctx ends.
func (s *AdminService) RunUserImportReaper(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		s.reapUserImports(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *AdminService) reapUserImports(ctx context.Context) {
	now := s.d.Now()
	jobs, err := s.d.UserImports.ReapStale(ctx, now.Add(-userImportStaleAfter), now)
	if err != nil && ctx.Err() == nil {
		s.d.Logger.Warn("user imports: cannot look for lost imports", "error", err)
	}
	for _, job := range jobs {
		s.d.Logger.Warn("user import: its process is gone, marked as interrupted", "job_id", job.ID, "processed", job.Processed, "total", job.Total)
		name := job.RealmID
		if realm, err := s.d.Realms.GetByID(ctx, job.RealmID); err == nil {
			name = realm.Name
		}
		s.announceUserImport(ctx, job, name)
	}
	if _, err := s.d.UserImports.DeleteFinishedBefore(ctx, now.Add(-userImportRetention)); err != nil && ctx.Err() == nil {
		s.d.Logger.Warn("user imports: cannot purge old reports", "error", err)
	}
}

// UserImportView is an import, as the console shows it. Rows comes once it
// is over: until then only the totals move.
type UserImportView struct {
	ID              string                  `json:"id"`
	Status          domain.UserImportStatus `json:"status"`
	FileName        string                  `json:"file_name"`
	RequestedByName string                  `json:"requested_by_name"`
	SendEmail       bool                    `json:"send_email"`
	NotifyWhenDone  bool                    `json:"notify_when_done"`
	Total           int                     `json:"total"`
	Processed       int                     `json:"processed"`
	Created         int                     `json:"created"`
	Failed          int                     `json:"failed"`
	IgnoredColumns  []string                `json:"ignored_columns"`
	Rows            []domain.UserImportRow  `json:"rows,omitempty"`
	// WithoutEmail: accounts created whose activation link was not e-mailed.
	WithoutEmail int        `json:"without_email"`
	CreatedAt    time.Time  `json:"created_at"`
	FinishedAt   *time.Time `json:"finished_at"`
}

func userImportView(j *domain.UserImportJob) *UserImportView {
	v := &UserImportView{
		ID: j.ID, Status: j.Status, FileName: j.FileName, RequestedByName: j.RequestedByName,
		SendEmail: j.SendEmail, NotifyWhenDone: j.NotifyWhenDone,
		Total: j.Total, Processed: j.Processed, Created: j.Created, Failed: j.Failed,
		IgnoredColumns: orEmpty(j.IgnoredColumns), CreatedAt: j.CreatedAt, FinishedAt: j.FinishedAt,
	}
	if j.Status != domain.UserImportRunning {
		v.Rows = j.Rows
	}
	for i := range j.Rows {
		if j.Rows[i].Status == domain.UserImportRowCreated && !j.Rows[i].Emailed {
			v.WithoutEmail++
		}
	}
	return v
}

// ListUserImports returns the latest imports of a realm, without their rows.
func (s *AdminService) ListUserImports(ctx context.Context, realm *domain.Realm) ([]*UserImportView, error) {
	jobs, err := s.d.UserImports.ListByRealm(ctx, realm.ID, userImportListSize)
	if err != nil {
		return nil, err
	}
	out := make([]*UserImportView, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, userImportView(j))
	}
	return out, nil
}

func (s *AdminService) userImportInRealm(ctx context.Context, realmID, id string) (*domain.UserImportJob, error) {
	job, err := s.d.UserImports.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && job.RealmID != realmID) {
		return nil, adminNotFound(i18n.M("admin.error.not_found.user_import", "import not found"))
	}
	return job, err
}

// GetUserImport returns where an import stands, or its report.
func (s *AdminService) GetUserImport(ctx context.Context, realm *domain.Realm, id string) (*UserImportView, error) {
	job, err := s.userImportInRealm(ctx, realm.ID, id)
	if err != nil {
		return nil, err
	}
	return userImportView(job), nil
}

// UserImportLink is the activation link of an imported account.
type UserImportLink struct {
	Line          int    `json:"line"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	ActivationURL string `json:"activation_url"`
}

// UserImportLinks: shown once; the links are not stored anywhere.
type UserImportLinks struct {
	Links     []UserImportLink `json:"links"`
	ExpiresAt *time.Time       `json:"expires_at"`
}

// UserImportActivationLinks issues the activation links of the accounts an
// import created without e-mail, those that have not chosen a password since.
// The database only ever holds the hash of a link, so the import cannot keep
// them for later: each call makes new ones, and the previous ones stop working.
func (s *AdminService) UserImportActivationLinks(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) (*UserImportLinks, error) {
	job, err := s.userImportInRealm(ctx, realm.ID, id)
	if err != nil {
		return nil, err
	}
	if job.Status == domain.UserImportRunning {
		return nil, adminText(AdminRefused, "import_running", "", i18n.M("admin.error.import_links_running", "the import is still running: the links are available when it ends"))
	}
	out := &UserImportLinks{Links: []UserImportLink{}}
	for i := range job.Rows {
		row := &job.Rows[i]
		if row.Status != domain.UserImportRowCreated || row.Emailed || row.UserID == "" {
			continue
		}
		u, err := s.userInRealm(ctx, realm.ID, row.UserID)
		if err != nil {
			if isAdminError(err) {
				continue // deleted since
			}
			return nil, err
		}
		if u.PasswordHash != "" {
			continue // activated since
		}
		res, err := s.issueActivationVia(ctx, actor, realm, u, false, true, nil)
		if err != nil {
			return nil, err
		}
		out.ExpiresAt = &res.ExpiresAt
		out.Links = append(out.Links, UserImportLink{Line: row.Line, Email: u.Email, Username: u.Username, ActivationURL: res.ActivationURL})
	}
	if len(out.Links) > 0 {
		s.auditAdmin(ctx, actor, realm.ID, audit.UserActivationLinkSent, "UserImportJob", job.ID, domain.AuditLogInfo, map[string]interface{}{
			"emailed": false, "links": len(out.Links), "expires_at": out.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// importChecker checks the lines of one file: the rules of an invitation,
// names of groups and roles, and what one line owes to the ones before it.
type importChecker struct {
	s            *AdminService
	realm        *domain.Realm
	groups       map[string]string // name -> id
	roles        map[string]string
	seenEmail    map[string]int // lowercase -> line
	seenUsername map[string]int
}

func (s *AdminService) newImportChecker(ctx context.Context, realm *domain.Realm) (*importChecker, error) {
	groups, err := s.d.Groups.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	roles, err := s.d.Roles.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	c := &importChecker{
		s: s, realm: realm, groups: make(map[string]string, len(groups)), roles: make(map[string]string, len(roles)),
		seenEmail: map[string]int{}, seenUsername: map[string]int{},
	}
	for _, g := range groups {
		c.groups[g.Name] = g.ID
	}
	for _, r := range roles {
		c.roles[r.Name] = r.ID
	}
	return c, nil
}

func (c *importChecker) check(ctx context.Context, row *importRow) (*invitedUser, error) {
	if row.err != nil {
		return nil, row.err
	}
	groupIDs := make([]string, 0, len(row.groups))
	for _, name := range row.groups {
		id, ok := c.groups[name]
		if !ok {
			return nil, adminInvalid("groups", i18n.M("admin.error.import_unknown_group", "there is no group \"{name}\" in this realm", "name", name))
		}
		groupIDs = append(groupIDs, id)
	}
	roleIDs := make([]string, 0, len(row.roles))
	for _, name := range row.roles {
		id, ok := c.roles[name]
		if !ok {
			return nil, adminInvalid("roles", i18n.M("admin.error.import_unknown_role", "there is no role \"{name}\" in this realm", "name", name))
		}
		roleIDs = append(roleIDs, id)
	}
	p, err := c.s.normalizeInvite(ctx, c.realm, InviteUserInput{
		Username: row.username, Email: row.email, Profile: row.profile, GroupIDs: groupIDs, RoleIDs: roleIDs,
	})
	if err != nil {
		return nil, err
	}
	// Before the database: at import time, the first of two equal lines is
	// already there, and "same as line 12" says more than "already used".
	email, username := strings.ToLower(p.email), strings.ToLower(p.username)
	if line, dup := c.seenEmail[email]; dup {
		return nil, adminInvalid("email", i18n.M("admin.error.import_same_email", "same e-mail as line {line}", "line", line))
	}
	if line, dup := c.seenUsername[username]; dup {
		return nil, adminInvalid("username", i18n.M("admin.error.import_same_username", "same username as line {line}", "line", line))
	}
	c.seenEmail[email], c.seenUsername[username] = row.line, row.line
	if err := c.s.checkUnique(ctx, c.realm.ID, "", p.username, p.email); err != nil {
		return nil, err
	}
	return p, nil
}

func baseImportRow(row *importRow) domain.UserImportRow {
	return domain.UserImportRow{Line: row.line, Email: row.email, Username: row.username}
}

func isAdminError(err error) bool {
	var ae *AdminError
	return errors.As(err, &ae)
}

// importErrorText is the sentence of a refused line. Anything but an
// AdminError is a server problem: logged, never shown.
func (s *AdminService) importErrorText(ctx context.Context, err error, loc *i18n.Localizer) string {
	var ae *AdminError
	if errors.As(err, &ae) {
		if ae.Text.Key != "" {
			return loc.Text(ae.Text)
		}
		return ae.Message
	}
	s.d.Logger.ErrorContext(ctx, "user import: line failed", "error", err)
	return loc.Text(i18n.M("admin.error.internal", "something went wrong on the server, see its logs"))
}

// cleanImportFileName keeps the name for display: no folders, no control
// characters (it ends up in an e-mail and in the audit log).
func cleanImportFileName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name))
	if runes := []rune(name); len(runes) > maxImportFileName {
		name = string(runes[:maxImportFileName])
	}
	return name
}
