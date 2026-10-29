package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Timeouts: temporary suspensions set by an administrator on a user, a
// group (every member) or a client.
//
// Two mechanisms, on purpose:
//
//  1. The check. Every sign-in (password, passkey) and every token (new
//     assertion, refresh) asks ActiveTimeout first. This is what makes a
//     timeout effective, from its first second to its last.
//  2. The sign-out. When a timeout starts, its targets' sessions are
//     revoked (and with them their tokens), or for a client, every token
//     issued to it. Without it, access tokens issued just before would
//     stay usable until they expire. A timeout that starts at once is
//     enforced right away; a scheduled one by the enforcer (RunEnforcer),
//     within EnforcerInterval of its start.

// TimeoutChecker tells whether an admin-issued Timeout currently blocks a
// user (directly or through one of their groups) or the targeted client.
//
// The checker resolves the user's groups itself: callers only pass what they
// know (user + client), they don't have to know which groups to look at.
//
// clientRef may be empty (direct login on the IdP, no client involved yet).
type TimeoutChecker interface {
	// ActiveTimeout returns a timeout in force now that blocks userID or
	// clientRef, or nil. A timeout on the user (or one of their groups) is
	// returned before one on the client.
	ActiveTimeout(ctx context.Context, userID, clientRef string) (*domain.Timeout, error)
}

// NoActiveTimeouts never blocks anyone (tests, and services built without
// a timeout checker).
type NoActiveTimeouts struct{}

func (NoActiveTimeouts) ActiveTimeout(context.Context, string, string) (*domain.Timeout, error) {
	return nil, nil
}

// checkTimeout returns a *core.TimeoutError (errors.Is ErrTimeoutActive)
// when a timeout blocks the user or the client, any other error as is.
func checkTimeout(ctx context.Context, tc TimeoutChecker, userID, clientRef string) error {
	t, err := tc.ActiveTimeout(ctx, userID, clientRef)
	if err != nil {
		return err
	}
	if t == nil {
		return nil
	}
	return &core.TimeoutError{OnClient: !t.OnPeople()}
}

// Limits on what an administrator may set.
const (
	TimeoutReasonMaxLength = 500
	// TimeoutMaxLeadTime: how far ahead a timeout may be scheduled.
	TimeoutMaxLeadTime = 366 * 24 * time.Hour
	// TimeoutMinDuration: a shorter timeout is a mistake (or a lift).
	TimeoutMinDuration = time.Minute
	// timeoutStartSkew: a start this far in the past means "now" (the clock
	// of the admin's browser, the time to submit the form).
	timeoutStartSkew = 5 * time.Minute
	// EnforcerInterval: how often scheduled timeouts are looked at.
	EnforcerInterval = 30 * time.Second
	enforcerBatch    = 50
	// TimeoutEnforcerActor is the actor of sign-outs done by the enforcer.
	TimeoutEnforcerActor = "system:timeout-enforcer"
)

// TimeoutRefusal: a timeout change refused because of what was asked (bad
// input, a guardrail). Code is stable, Message is a sentence for humans.
type TimeoutRefusal struct {
	Code    string // invalid_request, not_found, timeout_over, timeout_self, timeout_admin_console
	Field   string // the input at fault, when there is one
	Message string
}

func (e *TimeoutRefusal) Error() string { return e.Message }

func timeoutInvalid(field, format string, a ...any) error {
	return &TimeoutRefusal{Code: "invalid_request", Field: field, Message: fmt.Sprintf(format, a...)}
}

var errTimeoutNotFound = &TimeoutRefusal{Code: "not_found", Message: "timeout not found"}

var errTimeoutOver = &TimeoutRefusal{Code: "timeout_over",
	Message: "this timeout is over (ended or lifted): it cannot be changed, create a new one instead"}

// TimeoutActor is who changes a timeout.
type TimeoutActor struct {
	By string // "user:<id>" (admin console), "cli:<os user>"
	// UserID: the administrator (user of the master realm) behind the change,
	// empty from the command line. They can never suspend themselves.
	UserID string
}

// TimeoutTarget is the user, group or client of a timeout, with its name.
type TimeoutTarget struct {
	Type domain.TimeoutTargetType
	ID   string
	Name string // username, group name, client name; the id when it is gone
}

// TimeoutSignOut counts what the start of a timeout revoked.
type TimeoutSignOut struct {
	Users    int `json:"users"`    // users who had at least one session
	Sessions int `json:"sessions"` // sessions revoked (their tokens with them)
	Tokens   int `json:"tokens"`   // tokens revoked (timeout on a client)
}

// TimeoutChange is the result of a create, update or lift.
type TimeoutChange struct {
	Timeout *domain.Timeout
	Target  TimeoutTarget
	// SignOut: the timeout started at once and its targets were signed out.
	SignOut *TimeoutSignOut
	// SignOutPending: it started at once but the sign-out failed; the
	// enforcer tries again (the checks block the targets meanwhile).
	SignOutPending bool
	// Changed: for an update, the fields that changed ("reason", "ends_at").
	Changed []string
}

type TimeoutDeps struct {
	Timeouts repository.TimeoutRepository
	Users    repository.UserRepository
	Groups   repository.GroupRepository
	Clients  repository.ClientRepository
	Tokens   repository.TokenRepository
	// Sessions revokes the sessions of the targets (it needs the session
	// cache). nil or Tokens nil: this process signs nobody out, the
	// enforcer of a running server does it within EnforcerInterval (the
	// checks block every new sign-in and token meanwhile). The command line
	// without VALKEY_ADDR works that way.
	Sessions *SessionService
	Audit    repository.AuditLogRepository // optional
	Now      func() time.Time
	Logger   *slog.Logger
}

// TimeoutService checks, creates, changes and lifts timeouts, and signs out
// their targets when they start.
type TimeoutService struct {
	d TimeoutDeps
}

func NewTimeoutService(d TimeoutDeps) *TimeoutService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &TimeoutService{d: d}
}


// ActiveTimeout implements TimeoutChecker: one query, at every sign-in and
// token. An error is returned as is: callers refuse the sign-in (fail
// closed), they never let it through.
func (s *TimeoutService) ActiveTimeout(ctx context.Context, userID, clientRef string) (*domain.Timeout, error) {
	rows, err := s.d.Timeouts.InForce(ctx, userID, clientRef, s.d.Now())
	if err != nil {
		return nil, fmt.Errorf("timeouts: %w", err)
	}
	var onClient *domain.Timeout
	for _, t := range rows {
		if t.OnPeople() {
			return t, nil
		}
		if onClient == nil {
			onClient = t
		}
	}
	return onClient, nil
}


// List returns a page of a realm's timeouts, latest start first, and the
// total. current: true for the scheduled and active ones, false for the
// others, nil for all.
func (s *TimeoutService) List(ctx context.Context, realmID string, current *bool, page repository.Page) ([]*domain.Timeout, int, error) {
	return s.d.Timeouts.ListByRealm(ctx, realmID, repository.TimeoutFilter{Current: current, At: s.d.Now()}, page)
}

// Get returns a timeout of the realm (a TimeoutRefusal not_found otherwise).
func (s *TimeoutService) Get(ctx context.Context, realmID, id string) (*domain.Timeout, error) {
	t, err := s.d.Timeouts.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && t.RealmID != realmID) {
		return nil, errTimeoutNotFound
	}
	return t, err
}

// Target resolves the name of a timeout's target. A target deleted since
// keeps its id as name.
func (s *TimeoutService) Target(ctx context.Context, t *domain.Timeout) TimeoutTarget {
	out := TimeoutTarget{Type: t.TargetType, ID: t.TargetID, Name: t.TargetID}
	switch t.TargetType {
	case domain.TimeoutTargetUser:
		if u, err := s.d.Users.GetByID(ctx, t.TargetID); err == nil {
			out.Name = u.Username
		}
	case domain.TimeoutTargetGroup:
		if g, err := s.d.Groups.GetByID(ctx, t.TargetID); err == nil {
			out.Name = g.Name
		}
	case domain.TimeoutTargetClientApp:
		if c, err := s.d.Clients.GetByID(ctx, t.TargetID); err == nil {
			out.Name = c.Name
		}
	}
	return out
}


type CreateTimeoutInput struct {
	Realm      *domain.Realm
	TargetType domain.TimeoutTargetType
	TargetID   string    // internal id of the user, group or client
	StartsAt   time.Time // zero (or a few minutes ago): now
	EndsAt     time.Time // zero: no end, until lifted
	Reason     string    // required: it is what the audit log keeps
	Actor      TimeoutActor
}

// Create records a timeout. When it starts at once, its targets are signed
// out before Create returns.
func (s *TimeoutService) Create(ctx context.Context, in CreateTimeoutInput) (*TimeoutChange, error) {
	if in.Realm == nil {
		return nil, errors.New("timeouts: create: no realm")
	}
	if in.Actor.By == "" {
		return nil, errors.New("timeouts: create: no actor")
	}
	if !in.TargetType.Valid() {
		return nil, timeoutInvalid("target_type", "the target must be a user, a group or a client")
	}
	reason, err := checkTimeoutReason(in.Reason)
	if err != nil {
		return nil, err
	}

	now := s.d.Now()
	starts := in.StartsAt
	switch {
	case starts.IsZero(), !starts.After(now):
		if !starts.IsZero() && starts.Before(now.Add(-timeoutStartSkew)) {
			return nil, timeoutInvalid("starts_at", "the start is in the past: leave it empty to start now")
		}
		starts = now
	case starts.After(now.Add(TimeoutMaxLeadTime)):
		return nil, timeoutInvalid("starts_at", "a timeout can be scheduled at most %d days ahead", int(TimeoutMaxLeadTime.Hours()/24))
	}
	if !in.EndsAt.IsZero() && in.EndsAt.Before(starts.Add(TimeoutMinDuration)) {
		return nil, timeoutInvalid("ends_at", "the end must come at least a minute after the start")
	}

	target, err := s.resolveTarget(ctx, in.Realm, in.TargetType, in.TargetID)
	if err != nil {
		return nil, err
	}
	if err := s.guard(ctx, in.Realm, target, in.Actor); err != nil {
		return nil, err
	}

	t, err := s.d.Timeouts.Create(ctx, repository.CreateTimeoutParams{
		RealmID: in.Realm.ID, TargetType: in.TargetType, TargetID: target.ID,
		StartsAt: starts, EndsAt: in.EndsAt, Reason: reason, CreatedBy: in.Actor.By,
	})
	if err != nil {
		return nil, fmt.Errorf("timeouts: create: %w", err)
	}
	out := &TimeoutChange{Timeout: t, Target: target}
	if t.InForceAt(s.d.Now()) && s.CanSignOut() {
		signOut, err := s.enforce(ctx, t, in.Actor.By)
		if err != nil {
			s.d.Logger.WarnContext(ctx, "timeouts: sign-out failed, the enforcer will try again",
				"timeout_id", t.ID, "error", err)
			out.SignOutPending = true
		}
		out.SignOut = signOut
	}
	return out, nil
}

// CanSignOut reports whether this service revokes sessions and tokens
// itself. false: a running server's enforcer does it (see TimeoutDeps).
func (s *TimeoutService) CanSignOut() bool { return s.d.Sessions != nil && s.d.Tokens != nil }

func checkTimeoutReason(v string) (string, error) {
	reason := strings.TrimSpace(v)
	switch {
	case reason == "":
		return "", timeoutInvalid("reason", "a reason is required: it is what the audit log keeps")
	case utf8.RuneCountInString(reason) > TimeoutReasonMaxLength:
		return "", timeoutInvalid("reason", "the reason is limited to %d characters", TimeoutReasonMaxLength)
	}
	return reason, nil
}

// resolveTarget checks that the target exists in the realm.
func (s *TimeoutService) resolveTarget(ctx context.Context, realm *domain.Realm, typ domain.TimeoutTargetType, id string) (TimeoutTarget, error) {
	out := TimeoutTarget{Type: typ, ID: id}
	notFound := &TimeoutRefusal{Code: "invalid_request", Field: "target_id", Message: "no such " + targetNoun(typ) + " in this realm"}
	if id == "" {
		return out, timeoutInvalid("target_id", "choose the %s to suspend", targetNoun(typ))
	}
	switch typ {
	case domain.TimeoutTargetUser:
		u, err := s.d.Users.GetByID(ctx, id)
		if errors.Is(err, repository.ErrNotFound) || (err == nil && (u.RealmID != realm.ID || u.DeletedAt != nil)) {
			return out, notFound
		}
		if err != nil {
			return out, err
		}
		out.Name = u.Username
	case domain.TimeoutTargetGroup:
		g, err := s.d.Groups.GetByID(ctx, id)
		if errors.Is(err, repository.ErrNotFound) || (err == nil && g.RealmID != realm.ID) {
			return out, notFound
		}
		if err != nil {
			return out, err
		}
		out.Name = g.Name
	case domain.TimeoutTargetClientApp:
		c, err := s.d.Clients.GetByID(ctx, id)
		if errors.Is(err, repository.ErrNotFound) || (err == nil && (c.RealmID != realm.ID || c.IsDeleted())) {
			return out, notFound
		}
		if err != nil {
			return out, err
		}
		out.Name = c.Name
	}
	return out, nil
}

func targetNoun(t domain.TimeoutTargetType) string {
	switch t {
	case domain.TimeoutTargetGroup:
		return "group"
	case domain.TimeoutTargetClientApp:
		return "client"
	}
	return "user"
}

// guard refuses what would lock administrators out of the admin console:
// their own account, a group of theirs, the "admins" group and the console's
// client. Recovery from the command line lifts anything anyway
// (`idp-admin recover timeouts`).
func (s *TimeoutService) guard(ctx context.Context, realm *domain.Realm, target TimeoutTarget, actor TimeoutActor) error {
	if !realm.IsSystemRealm {
		return nil // the admin console and its administrators live in master
	}
	self := &TimeoutRefusal{Code: "timeout_self", Field: "target_id"}
	console := &TimeoutRefusal{Code: "timeout_admin_console", Field: "target_id"}
	switch target.Type {
	case domain.TimeoutTargetUser:
		if actor.UserID != "" && target.ID == actor.UserID {
			self.Message = "you cannot suspend your own account"
			return self
		}
	case domain.TimeoutTargetGroup:
		if target.Name == AdminGroupName {
			console.Message = "the \"" + AdminGroupName + "\" group keeps the admin console usable: it cannot be suspended"
			return console
		}
		if actor.UserID != "" {
			members, err := s.d.Groups.ListMemberIDs(ctx, target.ID)
			if err != nil {
				return fmt.Errorf("timeouts: group members: %w", err)
			}
			if slices.Contains(members, actor.UserID) {
				self.Message = "you are a member of this group: suspending it would sign you out of the admin console"
				return self
			}
		}
	case domain.TimeoutTargetClientApp:
		c, err := s.d.Clients.GetByID(ctx, target.ID)
		if err != nil {
			return fmt.Errorf("timeouts: client: %w", err)
		}
		if c.ClientID == domain.InternalAdminClientID {
			console.Message = "the admin console's client (" + domain.InternalAdminClientID + ") cannot be suspended"
			return console
		}
	}
	return nil
}


type UpdateTimeoutInput struct {
	Realm  *domain.Realm
	ID     string
	Reason *string
	// EndsAt: nil leaves the end as it is; a zero time removes it (no end).
	EndsAt *time.Time
	Actor  TimeoutActor
}

// Update changes the reason and/or the end of a timeout that is not over.
// The start never changes: to move a scheduled timeout, lift it and create
// another.
func (s *TimeoutService) Update(ctx context.Context, in UpdateTimeoutInput) (*TimeoutChange, error) {
	t, err := s.Get(ctx, in.Realm.ID, in.ID)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	if t.Over(now) {
		return nil, errTimeoutOver
	}
	var p repository.UpdateTimeoutParams
	var changed []string
	if in.Reason != nil {
		reason, err := checkTimeoutReason(*in.Reason)
		if err != nil {
			return nil, err
		}
		if reason != t.Reason {
			p.Reason, changed = &reason, append(changed, "reason")
		}
	}
	if in.EndsAt != nil && !in.EndsAt.Equal(t.EndsAt) {
		end := *in.EndsAt
		if !end.IsZero() {
			floor := t.StartsAt
			if now.After(floor) {
				floor = now
			}
			if end.Before(floor.Add(TimeoutMinDuration)) {
				return nil, timeoutInvalid("ends_at", "the end must come at least a minute after the start and after now: to end it now, lift it")
			}
		}
		p.EndsAt, changed = &end, append(changed, "ends_at")
	}
	if len(changed) > 0 {
		t, err = s.d.Timeouts.Update(ctx, t.ID, p)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, errTimeoutOver // lifted meanwhile
		}
		if err != nil {
			return nil, fmt.Errorf("timeouts: update: %w", err)
		}
	}
	return &TimeoutChange{Timeout: t, Target: s.Target(ctx, t), Changed: changed}, nil
}

// Lift ends a timeout now (or cancels a scheduled one). Sessions revoked at
// its start stay revoked: people sign in again.
func (s *TimeoutService) Lift(ctx context.Context, realm *domain.Realm, id string, actor TimeoutActor) (*TimeoutChange, error) {
	t, err := s.Get(ctx, realm.ID, id)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	if t.Over(now) {
		return nil, errTimeoutOver
	}
	ok, err := s.d.Timeouts.Lift(ctx, t.ID, actor.By, now)
	if err != nil {
		return nil, fmt.Errorf("timeouts: lift: %w", err)
	}
	if !ok {
		return nil, errTimeoutOver // lifted or ended meanwhile
	}
	if t, err = s.d.Timeouts.GetByID(ctx, t.ID); err != nil {
		return nil, fmt.Errorf("timeouts: lift: %w", err)
	}
	return &TimeoutChange{Timeout: t, Target: s.Target(ctx, t)}, nil
}

// LiftAllInRealm lifts every timeout of the realm that is not over (the
// recovery command of the master realm). It returns the lifted ones.
func (s *TimeoutService) LiftAllInRealm(ctx context.Context, realm *domain.Realm, actor TimeoutActor) ([]*TimeoutChange, error) {
	current := true
	rows, _, err := s.List(ctx, realm.ID, &current, repository.Page{NoTotal: true})
	if err != nil {
		return nil, err
	}
	var out []*TimeoutChange
	for _, t := range rows {
		c, err := s.Lift(ctx, realm, t.ID, actor)
		if errors.Is(err, errTimeoutOver) {
			continue
		}
		if err != nil {
			return out, err
		}
		out = append(out, c)
	}
	return out, nil
}


// RunEnforcer signs out the targets of scheduled timeouts when they start,
// every `every`, until ctx is done. Several servers may run it: each
// timeout is enforced once (MarkEnforced is a conditional UPDATE).
func (s *TimeoutService) RunEnforcer(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if _, err := s.EnforceDue(ctx); err != nil && ctx.Err() == nil {
			s.d.Logger.WarnContext(ctx, "timeouts: enforcer", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// EnforceDue signs out the targets of every started timeout that was not
// enforced yet, and returns how many timeouts it enforced.
func (s *TimeoutService) EnforceDue(ctx context.Context) (int, error) {
	if !s.CanSignOut() {
		return 0, nil
	}
	due, err := s.d.Timeouts.ListToEnforce(ctx, s.d.Now(), enforcerBatch)
	if err != nil {
		return 0, fmt.Errorf("timeouts: due: %w", err)
	}
	n := 0
	var errs []error
	for _, t := range due {
		res, err := s.enforce(ctx, t, TimeoutEnforcerActor)
		if err != nil {
			errs = append(errs, fmt.Errorf("timeout %s: %w", t.ID, err))
			continue
		}
		if res != nil {
			n++
		}
	}
	return n, errors.Join(errs...)
}

// enforce claims the timeout (MarkEnforced), then revokes. A failure undoes
// the claim so that the enforcer tries again; revoking twice is harmless.
// It returns nil, nil when another process claimed it first.
func (s *TimeoutService) enforce(ctx context.Context, t *domain.Timeout, by string) (*TimeoutSignOut, error) {
	at := s.d.Now()
	claimed, err := s.d.Timeouts.MarkEnforced(ctx, t.ID, at)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, nil
	}
	res, err := s.signOut(ctx, t)
	if err != nil {
		if cerr := s.d.Timeouts.ClearEnforced(ctx, t.ID); cerr != nil {
			s.d.Logger.ErrorContext(ctx, "timeouts: cannot schedule the sign-out again", "timeout_id", t.ID, "error", cerr)
		}
		return nil, err
	}
	t.EnforcedAt = at
	s.auditEnforced(ctx, t, by, res)
	return res, nil
}

func (s *TimeoutService) signOut(ctx context.Context, t *domain.Timeout) (*TimeoutSignOut, error) {
	res := &TimeoutSignOut{}
	revokeUser := func(userID string) error {
		if s.d.Sessions == nil {
			return nil
		}
		n, err := s.d.Sessions.RevokeUserSessions(ctx, userID, domain.SessionRevokedTimeout)
		if err != nil {
			return err
		}
		if n > 0 {
			res.Users++
			res.Sessions += n
		}
		return nil
	}
	switch t.TargetType {
	case domain.TimeoutTargetUser:
		if err := revokeUser(t.TargetID); err != nil {
			return nil, err
		}
	case domain.TimeoutTargetGroup:
		members, err := s.d.Groups.ListMemberIDs(ctx, t.TargetID)
		if err != nil {
			return nil, fmt.Errorf("group members: %w", err)
		}
		for _, id := range members {
			if err := revokeUser(id); err != nil {
				return nil, err
			}
		}
	case domain.TimeoutTargetClientApp:
		if s.d.Tokens != nil {
			n, err := s.d.Tokens.RevokeByClient(ctx, t.TargetID)
			if err != nil {
				return nil, fmt.Errorf("revoke client tokens: %w", err)
			}
			res.Tokens = n
		}
	}
	return res, nil
}

func (s *TimeoutService) auditEnforced(ctx context.Context, t *domain.Timeout, by string, res *TimeoutSignOut) {
	if s.d.Audit == nil {
		return
	}
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      t.RealmID,
		Action:       "timeout_enforced",
		ResourceType: "Timeout",
		ResourceID:   t.ID,
		Level:        domain.AuditLogWarning,
		Status:       domain.AuditLogSuccess,
		Details: map[string]interface{}{
			"target_type": string(t.TargetType), "target_id": t.TargetID, "triggered_by": by,
			"users_signed_out": res.Users, "sessions_revoked": res.Sessions, "tokens_revoked": res.Tokens,
		},
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "timeouts: audit log write failed", "timeout_id", t.ID, "error", err)
	}
}
