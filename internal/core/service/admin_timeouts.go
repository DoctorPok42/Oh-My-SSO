package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Timeouts in the admin console: list, create, change the reason or the end,
// lift. The rules (validation, guardrails, sign-out at the start) live in
// TimeoutService; this file adds the views and the audit trail.

type TimeoutView struct {
	ID         string     `json:"id"`
	TargetType string     `json:"target_type"`
	Target     NameRef    `json:"target"`
	StartsAt   time.Time  `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at"` // nil: no end
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"` // administrator's username, or "cli:<os user>"
	CreatedAt  time.Time  `json:"created_at"`
	// Status: scheduled, active, ended or lifted.
	Status string `json:"status"`
	// Active: Status is "active" (in force now).
	Active     bool       `json:"active"`
	LiftedAt   *time.Time `json:"lifted_at"`
	LiftedBy   string     `json:"lifted_by"`
	EnforcedAt *time.Time `json:"enforced_at"` // when the targets were signed out
	// On a create that started at once: what was revoked, or that the
	// sign-out failed and will be retried (the checks block meanwhile).
	SignOut        *TimeoutSignOut `json:"sign_out,omitempty"`
	SignOutPending bool            `json:"sign_out_pending,omitempty"`
}

// TimeoutListStatus filters the list: "current" (scheduled and active, the
// default of the console), "past" (ended and lifted), "" for every one.
type TimeoutListStatus string

const (
	TimeoutListCurrent TimeoutListStatus = "current"
	TimeoutListPast    TimeoutListStatus = "past"
	TimeoutListAll     TimeoutListStatus = ""
)

// errNoTimeouts: AdminDeps.Timeouts was left nil (a wiring mistake).
var errNoTimeouts = errors.New("admin: timeouts are not configured")

func (s *AdminService) ListTimeouts(ctx context.Context, realm *domain.Realm, status TimeoutListStatus,
	page repository.Page) ([]TimeoutView, int, error) {
	if s.d.Timeouts == nil {
		return nil, 0, errNoTimeouts
	}
	var current *bool
	switch status {
	case TimeoutListCurrent:
		b := true
		current = &b
	case TimeoutListPast:
		b := false
		current = &b
	case TimeoutListAll:
	default:
		return nil, 0, adminInvalid("status", "status must be current, past or all")
	}
	rows, total, err := s.d.Timeouts.List(ctx, realm.ID, current, page)
	if err != nil {
		return nil, 0, err
	}
	names := s.timeoutNames()
	out := make([]TimeoutView, 0, len(rows))
	for _, t := range rows {
		out = append(out, s.timeoutView(ctx, t, names.target(ctx, s, t), names))
	}
	return out, total, nil
}

// GetTimeout returns one timeout of the realm (the console's drawer).
func (s *AdminService) GetTimeout(ctx context.Context, realm *domain.Realm, id string) (*TimeoutView, error) {
	if s.d.Timeouts == nil {
		return nil, errNoTimeouts
	}
	t, err := s.d.Timeouts.Get(ctx, realm.ID, id)
	if err != nil {
		return nil, asAdminError(err)
	}
	names := s.timeoutNames()
	v := s.timeoutView(ctx, t, names.target(ctx, s, t), names)
	return &v, nil
}

// TimeoutInput is a new timeout from the console.
type TimeoutInput struct {
	TargetType string
	TargetID   string
	StartsAt   time.Time // zero: now
	EndsAt     time.Time // zero: no end
	Reason     string
}

func (s *AdminService) CreateTimeout(ctx context.Context, actor AdminActor, realm *domain.Realm, in TimeoutInput) (*TimeoutView, error) {
	if s.d.Timeouts == nil {
		return nil, errNoTimeouts
	}
	c, err := s.d.Timeouts.Create(ctx, CreateTimeoutInput{
		Realm: realm, TargetType: domain.TimeoutTargetType(in.TargetType), TargetID: in.TargetID,
		StartsAt: in.StartsAt, EndsAt: in.EndsAt, Reason: in.Reason,
		Actor: TimeoutActor{By: actor.By(), UserID: actor.UserID},
	})
	if err != nil {
		return nil, asAdminError(err)
	}
	details := map[string]interface{}{
		"target_type": string(c.Target.Type), "target_id": c.Target.ID, "target_name": c.Target.Name,
		"starts_at": c.Timeout.StartsAt.UTC().Format(time.RFC3339), "ends_at": formatEnd(c.Timeout.EndsAt),
		"reason": c.Timeout.Reason,
	}
	if c.SignOut != nil {
		details["sessions_revoked"], details["tokens_revoked"] = c.SignOut.Sessions, c.SignOut.Tokens
	}
	s.auditAdmin(ctx, actor, realm.ID, "timeout.create", "Timeout", c.Timeout.ID, domain.AuditLogWarning, details)
	v := s.changeView(ctx, c)
	return &v, nil
}

// UpdateTimeout changes the reason and/or the end. endsAt: nil leaves the
// end as it is, a zero time removes it (no end).
func (s *AdminService) UpdateTimeout(ctx context.Context, actor AdminActor, realm *domain.Realm, id string,
	reason *string, endsAt *time.Time) (*TimeoutView, error) {
	if s.d.Timeouts == nil {
		return nil, errNoTimeouts
	}
	c, err := s.d.Timeouts.Update(ctx, UpdateTimeoutInput{Realm: realm, ID: id, Reason: reason, EndsAt: endsAt,
		Actor: TimeoutActor{By: actor.By(), UserID: actor.UserID}})
	if err != nil {
		return nil, asAdminError(err)
	}
	if len(c.Changed) > 0 {
		s.auditAdmin(ctx, actor, realm.ID, "timeout.update", "Timeout", c.Timeout.ID, domain.AuditLogWarning,
			map[string]interface{}{"changed": c.Changed, "target_type": string(c.Target.Type), "target_name": c.Target.Name,
				"ends_at": formatEnd(c.Timeout.EndsAt)})
	}
	v := s.changeView(ctx, c)
	return &v, nil
}

func (s *AdminService) LiftTimeout(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) (*TimeoutView, error) {
	if s.d.Timeouts == nil {
		return nil, errNoTimeouts
	}
	c, err := s.d.Timeouts.Lift(ctx, realm, id, TimeoutActor{By: actor.By(), UserID: actor.UserID})
	if err != nil {
		return nil, asAdminError(err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "timeout.lift", "Timeout", c.Timeout.ID, domain.AuditLogWarning,
		map[string]interface{}{"target_type": string(c.Target.Type), "target_name": c.Target.Name})
	v := s.changeView(ctx, c)
	return &v, nil
}

// RecoverTimeouts lifts every timeout of the master realm that is not over
// (`idp-admin recover timeouts`): the way back when a timeout locked the
// administrators out anyway (a group of theirs suspended from the command
// line, say). Every administrator is alerted. It returns the lifted ones.
func (s *AdminService) RecoverTimeouts(ctx context.Context, actor string) ([]TimeoutView, int, error) {
	if s.d.Timeouts == nil {
		return nil, 0, errNoTimeouts
	}
	realm, admins, err := s.bootstrappedMaster(ctx)
	if err != nil {
		return nil, 0, err
	}
	lifted, err := s.d.Timeouts.LiftAllInRealm(ctx, realm, TimeoutActor{By: actor})
	names := s.timeoutNames()
	out := make([]TimeoutView, 0, len(lifted))
	for _, c := range lifted {
		out = append(out, s.timeoutView(ctx, c.Timeout, c.Target, names))
		s.writeCLIAudit(ctx, realm.ID, "recovery_timeout_lift", "Timeout", c.Timeout.ID, actor, map[string]interface{}{
			"target_type": string(c.Target.Type), "target_name": c.Target.Name})
	}
	if err != nil {
		return out, 0, fmt.Errorf("recover timeouts: %w", err)
	}
	current, err := s.d.Admin.ActiveGroupMemberIDs(ctx, admins.ID)
	if err != nil {
		return out, 0, nil // the timeouts are lifted: do not hide it because of the alert
	}
	if len(out) > 0 {
		s.alertAdmins(ctx, realm.ID, current, "every timeout of the master realm lifted", actor, "")
	}
	return out, len(current), nil
}

func (s *AdminService) changeView(ctx context.Context, c *TimeoutChange) TimeoutView {
	v := s.timeoutView(ctx, c.Timeout, c.Target, s.timeoutNames())
	v.SignOut, v.SignOutPending = c.SignOut, c.SignOutPending
	return v
}

func (s *AdminService) timeoutView(ctx context.Context, t *domain.Timeout, target TimeoutTarget, names *timeoutNames) TimeoutView {
	now := s.d.Now()
	status := t.StatusAt(now)
	v := TimeoutView{
		ID: t.ID, TargetType: string(t.TargetType), Target: NameRef{ID: target.ID, Name: target.Name},
		StartsAt: t.StartsAt, Reason: t.Reason, CreatedBy: names.actor(ctx, s, t.CreatedBy), CreatedAt: t.CreatedAt,
		Status: string(status), Active: status == domain.TimeoutActive,
		EndsAt: timePtr(t.EndsAt), LiftedAt: timePtr(t.LiftedAt), EnforcedAt: timePtr(t.EnforcedAt),
	}
	if t.LiftedBy != "" {
		v.LiftedBy = names.actor(ctx, s, t.LiftedBy)
	}
	return v
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func formatEnd(t time.Time) string {
	if t.IsZero() {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}

// timeoutNames resolves, once per id within a request, the names a list
// shows: targets, and the administrators behind "user:<id>".
type timeoutNames struct {
	targets map[string]TimeoutTarget
	actors  map[string]string
}

func (s *AdminService) timeoutNames() *timeoutNames {
	return &timeoutNames{targets: map[string]TimeoutTarget{}, actors: map[string]string{}}
}

func (n *timeoutNames) target(ctx context.Context, s *AdminService, t *domain.Timeout) TimeoutTarget {
	key := string(t.TargetType) + ":" + t.TargetID
	if v, ok := n.targets[key]; ok {
		return v
	}
	v := s.d.Timeouts.Target(ctx, t)
	n.targets[key] = v
	return v
}

// actor turns "user:<id>" into the administrator's username; anything else
// ("cli:alice", "system:...") is shown as recorded.
func (n *timeoutNames) actor(ctx context.Context, s *AdminService, by string) string {
	id, ok := strings.CutPrefix(by, "user:")
	if !ok {
		return by
	}
	if v, ok := n.actors[id]; ok {
		return v
	}
	name := by
	if u, err := s.d.Users.GetByID(ctx, id); err == nil {
		name = u.Username
	} else if !errors.Is(err, repository.ErrNotFound) {
		s.d.Logger.WarnContext(ctx, "admin: timeout actor lookup", "user_id", id, "error", err)
	}
	n.actors[id] = name
	return name
}

// timeoutAdminError maps a TimeoutRefusal to the Admin API's errors.
func timeoutAdminError(tr *TimeoutRefusal) *AdminError {
	switch tr.Code {
	case "not_found":
		return &AdminError{Kind: AdminNotFound, Code: "not_found", Message: tr.Message}
	case "invalid_request":
		return &AdminError{Kind: AdminInvalid, Code: "invalid_request", Field: tr.Field, Message: tr.Message}
	}
	return &AdminError{Kind: AdminRefused, Code: tr.Code, Field: tr.Field, Message: tr.Message}
}
