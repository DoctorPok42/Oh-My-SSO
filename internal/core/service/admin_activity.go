package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Sessions, audit log, dashboard, MFA policies and timeouts in the Admin
// API (Step 14).

// --- sessions -------------------------------------------------------------------

// SessionView: a row of the sessions table.
type SessionView struct {
	ID             string    `json:"id"`
	User           NameRef   `json:"user"`
	UserEmail      string    `json:"user_email"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	Device         string    `json:"device"`      // "Firefox on Windows", filled by the HTTP layer
	AuthMethod     string    `json:"auth_method"` // RFC 8176 value: pwd, hwk, swk, otp, mfa
	MFAVerified    bool      `json:"mfa_verified"`
	MFAMethod      string    `json:"mfa_method"`
	Clients        []NameRef `json:"clients"` // applications holding a live token
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// SessionFilter: the filters of the sessions screen.
type SessionFilter struct {
	UserID    string
	ClientRef string
	Page      repository.Page
}

func (s *AdminService) ListSessions(ctx context.Context, realm *domain.Realm, f SessionFilter) ([]SessionView, int, error) {
	st, err := s.settingsOf(ctx, realm.ID)
	if err != nil {
		return nil, 0, err
	}
	idle := time.Duration(st.SessionIdleMinutes) * time.Minute
	if idle <= 0 {
		idle = defaultSessionIdleTimeout
	}
	now := s.d.Now()
	sessions, total, err := s.d.Admin.SearchSessions(ctx, repository.SessionSearch{
		RealmID: realm.ID, UserID: f.UserID, ClientRef: f.ClientRef, Now: now, IdleSince: now.Add(-idle), Page: f.Page,
	})
	if err != nil {
		return nil, 0, err
	}
	sessionIDs := make([]string, 0, len(sessions))
	userIDs := []string{}
	for _, se := range sessions {
		sessionIDs = append(sessionIDs, se.ID)
		if !slices.Contains(userIDs, se.UserID) {
			userIDs = append(userIDs, se.UserID)
		}
	}
	users, err := s.d.Admin.UsersByIDs(ctx, userIDs)
	if err != nil {
		return nil, 0, err
	}
	byID := map[string]*domain.User{}
	for _, u := range users {
		byID[u.ID] = u
	}
	clients, err := s.d.Admin.SessionClients(ctx, sessionIDs, now)
	if err != nil {
		return nil, 0, err
	}
	names := map[string]string{}
	out := make([]SessionView, 0, len(sessions))
	for _, se := range sessions {
		v := SessionView{ID: se.ID, User: NameRef{ID: se.UserID}, IPAddress: se.IPAddress, UserAgent: se.UserAgent,
			AuthMethod: se.AuthMethod, MFAVerified: se.MFAVerified, MFAMethod: se.MFAMethodType, Clients: []NameRef{},
			CreatedAt: se.CreatedAt, LastActivityAt: se.LastActivityAt, ExpiresAt: se.ExpiresAt}
		if u := byID[se.UserID]; u != nil {
			v.User.Name, v.UserEmail = u.Username, u.Email
		}
		for _, ref := range clients[se.ID] {
			if _, ok := names[ref]; !ok {
				if c, err := s.d.Clients.GetByID(ctx, ref); err == nil {
					names[ref] = c.Name
				}
			}
			v.Clients = append(v.Clients, NameRef{ID: ref, Name: names[ref]})
		}
		out = append(out, v)
	}
	return out, total, nil
}

// RevokeSession signs a user out of one session (and its tokens).
func (s *AdminService) RevokeSession(ctx context.Context, actor AdminActor, realm *domain.Realm, sessionID string) error {
	se, err := s.d.Sessions.GetActive(ctx, sessionID)
	if errors.Is(err, ErrSessionInvalid) || (err == nil && se.RealmID != realm.ID) {
		return adminNotFound("session")
	}
	if err != nil {
		return err
	}
	if err := s.d.Sessions.Revoke(ctx, se.ID, domain.SessionRevokedAdminRevoked); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "session.revoke", "Session", se.ID, domain.AuditLogWarning, map[string]interface{}{
		"user_id": se.UserID,
	})
	return nil
}

// RevokeUserSessions signs a user out everywhere.
func (s *AdminService) RevokeUserSessions(ctx context.Context, actor AdminActor, realm *domain.Realm, userID string) error {
	u, err := s.userInRealm(ctx, realm.ID, userID)
	if err != nil {
		return err
	}
	if err := s.d.Sessions.RevokeAllForUser(ctx, u.ID, domain.SessionRevokedAdminRevoked); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "session.revoke_all", "User", u.ID, domain.AuditLogWarning, nil)
	return nil
}

// --- audit log ------------------------------------------------------------------

// AuditView: an audit entry, with the actor's name resolved (an admin of
// the master realm, a user of the realm, or the system).
type AuditView struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Action       string                 `json:"action"`
	Actor        *AuditActor            `json:"actor"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Status       string                 `json:"status"`
	Level        string                 `json:"level"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	Details      map[string]interface{} `json:"details"`
}

type AuditActor struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Admin    bool   `json:"admin"` // an administrator of the master realm
}

func (s *AdminService) SearchAudit(ctx context.Context, realm *domain.Realm, f repository.AuditSearch) ([]AuditView, int, error) {
	f.RealmID = realm.ID
	rows, total, err := s.d.Admin.SearchAuditLogs(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	ids := []string{}
	for _, r := range rows {
		if r.UserID != "" && !slices.Contains(ids, r.UserID) {
			ids = append(ids, r.UserID)
		}
	}
	users, err := s.d.Admin.UsersByIDs(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	byID := map[string]*domain.User{}
	for _, u := range users {
		byID[u.ID] = u
	}
	out := make([]AuditView, 0, len(rows))
	for _, r := range rows {
		v := AuditView{ID: r.ID, Timestamp: r.Timestamp, Action: r.Action, ResourceType: r.ResourceType,
			ResourceID: r.ResourceID, Status: string(r.Status), Level: string(r.Level), IPAddress: r.IPAddress,
			UserAgent: r.UserAgent, Details: r.Details}
		if v.Details == nil {
			v.Details = map[string]interface{}{}
		}
		if r.UserID != "" {
			a := &AuditActor{ID: r.UserID}
			if u := byID[r.UserID]; u != nil {
				a.Username = u.Username
				a.Admin = u.RealmID != realm.ID // the admin console's accounts live in master
			}
			v.Actor = a
		}
		out = append(out, v)
	}
	return out, total, nil
}

// --- dashboard ------------------------------------------------------------------

// Dashboard: the KPIs of a realm. Infrastructure health is added by the
// HTTP layer (it pings Postgres, Valkey, the KMS, SMTP and the public server).
type Dashboard struct {
	ActiveSessions int              `json:"active_sessions"`
	ActiveClients  int              `json:"active_clients"`
	Logins24h      LoginStats       `json:"logins_24h"`
	MFA            MFACoverage      `json:"mfa"`
	SigningKeys    []SigningKeyInfo `json:"signing_keys"`
	RecentActivity []AuditView      `json:"recent_activity"`
}

type LoginStats struct {
	Success int `json:"success"`
	Failure int `json:"failure"`
	// SuccessRate in percent, -1 when there was no attempt.
	SuccessRate float64 `json:"success_rate"`
}

type MFACoverage struct {
	Enrolled int     `json:"enrolled"`
	Total    int     `json:"total"`
	Percent  float64 `json:"percent"`
}

type SigningKeyInfo struct {
	Kid       string    `json:"kid"`
	KeyType   string    `json:"key_type"`
	Purpose   string    `json:"purpose"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *AdminService) Dashboard(ctx context.Context, realm *domain.Realm) (*Dashboard, error) {
	d := &Dashboard{SigningKeys: []SigningKeyInfo{}}
	_, total, err := s.ListSessions(ctx, realm, SessionFilter{Page: repository.Page{Limit: 1}})
	if err != nil {
		return nil, err
	}
	d.ActiveSessions = total
	if d.ActiveClients, err = s.d.Admin.CountActiveClients(ctx, realm.ID); err != nil {
		return nil, err
	}
	ok, ko, err := s.d.Admin.LoginCounts(ctx, realm.ID, s.d.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	d.Logins24h = LoginStats{Success: ok, Failure: ko, SuccessRate: -1}
	if ok+ko > 0 {
		d.Logins24h.SuccessRate = round1(100 * float64(ok) / float64(ok+ko))
	}
	enrolled, users, err := s.d.Admin.MFACoverage(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	d.MFA = MFACoverage{Enrolled: enrolled, Total: users}
	if users > 0 {
		d.MFA.Percent = round1(100 * float64(enrolled) / float64(users))
	}
	keys, err := s.d.KeyRotation.List(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Status == domain.SigningKeyActive {
			d.SigningKeys = append(d.SigningKeys, SigningKeyInfo{Kid: k.Kid, KeyType: string(k.KeyType),
				Purpose: string(k.Purpose), Status: string(k.Status), CreatedAt: k.CreatedAt})
		}
	}
	if d.RecentActivity, _, err = s.SearchAudit(ctx, realm, repository.AuditSearch{Page: repository.Page{Limit: 6}}); err != nil {
		return nil, err
	}
	return d, nil
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// --- MFA policies ---------------------------------------------------------------

// MFAPoliciesView: the MFA Policies screen.
type MFAPoliciesView struct {
	RequiredGlobally    bool             `json:"required_globally"`
	StepUpMaxAgeMinutes int              `json:"step_up_max_age_minutes"`
	Roles               []RolePolicyView `json:"roles"`
	Clients             []ClientPolicy   `json:"clients"`
	KnownMethods        []string         `json:"known_methods"`
}

type RolePolicyView struct {
	Role                      NameRef  `json:"role"`
	Configured                bool     `json:"configured"`
	Required                  bool     `json:"required"`
	AllowedMethods            []string `json:"allowed_methods"`
	EnrollmentGraceDays       int      `json:"enrollment_grace_days"`
	StepUpForSensitiveActions bool     `json:"step_up_for_sensitive_actions"`
	ManagedBy                 string   `json:"managed_by"`
}

type ClientPolicy struct {
	Client  NameRef  `json:"client"`
	Policy  string   `json:"policy"`
	Methods []string `json:"methods"`
}

// MFAPolicies lists the realm policy, a line per role (configured or not),
// and the clients with their own policy.
func (s *AdminService) MFAPolicies(ctx context.Context, realm *domain.Realm) (*MFAPoliciesView, error) {
	ov, err := s.d.MFAPolicy.Overview(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	v := &MFAPoliciesView{RequiredGlobally: ov.RequiredGlobally, StepUpMaxAgeMinutes: int(ov.StepUpMaxAge / time.Minute),
		Roles: []RolePolicyView{}, Clients: []ClientPolicy{}, KnownMethods: methodNames(domain.KnownMfaMethodTypes)}
	byRole := map[string]*domain.MfaPolicy{}
	for _, r := range ov.Roles {
		byRole[r.Policy.RoleID] = r.Policy
	}
	roles, err := s.d.Roles.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		line := RolePolicyView{Role: NameRef{ID: r.ID, Name: r.Name}, AllowedMethods: []string{}, ManagedBy: string(domain.MfaPolicyManagedByUI)}
		if p := byRole[r.ID]; p != nil {
			line.Configured, line.Required = true, p.Required
			line.AllowedMethods = methodNames(p.AllowedMethods)
			line.EnrollmentGraceDays, line.StepUpForSensitiveActions = p.EnrollmentGraceDays, p.StepUpForSensitiveActions
			line.ManagedBy = string(p.ManagedBy)
		}
		v.Roles = append(v.Roles, line)
	}
	for _, c := range ov.Clients {
		v.Clients = append(v.Clients, ClientPolicy{Client: NameRef{ID: c.ID, Name: c.Name}, Policy: string(c.MFAPolicy), Methods: methodNames(c.MFAAllowedMethods)})
	}
	return v, nil
}

// SetRealmMFA changes the realm-wide policy.
func (s *AdminService) SetRealmMFA(ctx context.Context, actor AdminActor, realm *domain.Realm, required *bool, stepUpMinutes *int) (*MFAPoliciesView, error) {
	if isMaster(realm) && required != nil && !*required {
		return nil, adminRefused("system_realm", "MFA stays required in the master realm")
	}
	var maxAge *time.Duration
	if stepUpMinutes != nil {
		d := time.Duration(*stepUpMinutes) * time.Minute
		maxAge = &d
	}
	if _, err := s.d.MFAPolicy.SetRealmPolicy(ctx, SetRealmMFAPolicyInput{RealmID: realm.ID, RequiredGlobally: required,
		StepUpMaxAge: maxAge, Actor: PolicyActor{TriggeredBy: actor.By()}}); err != nil {
		return nil, asAdminError(err)
	}
	return s.MFAPolicies(ctx, realm)
}

// RolePolicyInput: the policy of one role.
type RolePolicyInput struct {
	Required                  bool
	AllowedMethods            []string
	EnrollmentGraceDays       int
	StepUpForSensitiveActions bool
}

func (s *AdminService) SetRoleMFA(ctx context.Context, actor AdminActor, realm *domain.Realm, roleID string, in RolePolicyInput) (*MFAPoliciesView, error) {
	r, err := s.roleInRealm(ctx, realm.ID, roleID)
	if err != nil {
		return nil, err
	}
	methods := []domain.MfaMethodType{}
	for _, m := range in.AllowedMethods {
		methods = append(methods, domain.MfaMethodType(m))
	}
	if _, err := s.d.MFAPolicy.SetRolePolicy(ctx, SetRoleMFAPolicyInput{RealmID: realm.ID, RoleName: r.Name,
		Required: in.Required, AllowedMethods: methods, EnrollmentGraceDays: in.EnrollmentGraceDays,
		StepUpForSensitiveActions: in.StepUpForSensitiveActions, Actor: PolicyActor{TriggeredBy: actor.By()}}); err != nil {
		return nil, asAdminError(err)
	}
	return s.MFAPolicies(ctx, realm)
}

func (s *AdminService) DeleteRoleMFA(ctx context.Context, actor AdminActor, realm *domain.Realm, roleID string) (*MFAPoliciesView, error) {
	r, err := s.roleInRealm(ctx, realm.ID, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.d.MFAPolicy.DeleteRolePolicy(ctx, realm.ID, r.Name, PolicyActor{TriggeredBy: actor.By()}); err != nil &&
		!errors.Is(err, repository.ErrNotFound) {
		return nil, asAdminError(err)
	}
	return s.MFAPolicies(ctx, realm)
}

// --- timeouts (read-only in Step 14) ---------------------------------------------

// TimeoutView: a temporary restriction. Creating them comes with the real
// enforcement at login, in a later step (spec: Phase 2).
type TimeoutView struct {
	ID         string     `json:"id"`
	TargetType string     `json:"target_type"`
	Target     NameRef    `json:"target"`
	StartsAt   time.Time  `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at"` // nil: no end
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	Active     bool       `json:"active"`
}

func (s *AdminService) ListTimeouts(ctx context.Context, realm *domain.Realm) ([]TimeoutView, error) {
	rows, err := s.d.Admin.ListTimeouts(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	out := make([]TimeoutView, 0, len(rows))
	for _, t := range rows {
		v := TimeoutView{ID: t.ID, TargetType: string(t.TargetType), Target: NameRef{ID: t.TargetID, Name: t.TargetID},
			StartsAt: t.StartsAt, Reason: t.Reason, CreatedBy: t.CreatedBy}
		if !t.EndsAt.IsZero() {
			e := t.EndsAt
			v.EndsAt = &e
		}
		v.Active = !now.Before(t.StartsAt) && (t.EndsAt.IsZero() || now.Before(t.EndsAt))
		switch t.TargetType {
		case domain.TimeoutTargetUser:
			if u, err := s.d.Users.GetByID(ctx, t.TargetID); err == nil {
				v.Target.Name = u.Username
			}
		case domain.TimeoutTargetGroup:
			if g, err := s.d.Groups.GetByID(ctx, t.TargetID); err == nil {
				v.Target.Name = g.Name
			}
		case domain.TimeoutTargetClientApp:
			if c, err := s.d.Clients.GetByID(ctx, t.TargetID); err == nil {
				v.Target.Name = c.Name
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// --- signing keys ---------------------------------------------------------------

// SigningKeys lists every key of the realm (moved from the public server).
func (s *AdminService) SigningKeys(ctx context.Context, realm *domain.Realm) ([]*domain.SigningKey, error) {
	return s.d.KeyRotation.List(ctx, realm.ID)
}
