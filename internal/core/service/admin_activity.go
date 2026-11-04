package service

import (
	"sso.internal/sso/internal/i18n"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)



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
	RememberMe     bool      `json:"remember_me"` // "Keep me signed in" was ticked
	Clients        []NameRef `json:"clients"`     // applications holding a live token
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	// TrustedDevice: the second factor was skipped, the device is trusted
	// ("Don't ask again on this device").
	TrustedDevice bool `json:"trusted_device"`
}

// SessionFilter: the filters of the sessions screen.
type SessionFilter struct {
	UserID    string
	ClientRef string
	Page      repository.Page
}

func (s *AdminService) ListSessions(ctx context.Context, realm *domain.Realm, f SessionFilter) ([]SessionView, int, error) {
	win, err := s.activeWindow(ctx, realm)
	if err != nil {
		return nil, 0, err
	}
	now := win.Now
	win.UserID, win.ClientRef, win.Page = f.UserID, f.ClientRef, f.Page
	sessions, total, err := s.d.Admin.SearchSessions(ctx, win)
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
			AuthMethod: se.AuthMethod, MFAVerified: se.MFAVerified, MFAMethod: se.MFAMethodType, RememberMe: se.RememberMe, Clients: []NameRef{},
			CreatedAt: se.CreatedAt, LastActivityAt: se.LastActivityAt, ExpiresAt: se.ExpiresAt}
		v.TrustedDevice = se.TrustedDevice
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
		return adminNotFound(i18n.M("admin.error.not_found.session", "session not found"))
	}
	if err != nil {
		return err
	}
	if err := s.d.Sessions.Revoke(ctx, se.ID, domain.SessionRevokedAdminRevoked); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	s.auditAdminAbout(ctx, actor, realm.ID, se.UserID, audit.SessionRevoked, "Session", se.ID, domain.AuditLogWarning, map[string]interface{}{
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
	s.auditAdmin(ctx, actor, realm.ID, audit.SessionRevokedAll, "User", u.ID, domain.AuditLogWarning, nil)
	return nil
}


// AuditView: an audit entry, with the names resolved. Actor is who did it
// (nil when nobody: the server itself, or a failed sign-in), ActorType
// tells which kind of actor it is; Target is the user it is about (nil:
// none), Resource the object it changed.
type AuditView struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Action       string                 `json:"action"`
	ActorType    domain.AuditActorType  `json:"actor_type"`
	Actor        *AuditActor            `json:"actor"`
	Target       *AuditUserRef          `json:"target"`
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

// AuditUserRef names a user; Username is empty when the account is gone.
type AuditUserRef struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (s *AdminService) SearchAudit(ctx context.Context, realm *domain.Realm, f repository.AuditSearch) ([]AuditView, int, error) {
	f.RealmID = realm.ID
	rows, total, err := s.d.Admin.SearchAuditLogs(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	out, err := s.auditViews(ctx, rows)
	return out, total, err
}

func (s *AdminService) auditViews(ctx context.Context, rows []*domain.AuditLog) ([]AuditView, error) {
	ids := []string{}
	for _, r := range rows {
		for _, id := range []string{r.UserID, r.TargetUserID} {
			if id != "" && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	users, err := s.d.Admin.UsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := map[string]*domain.User{}
	for _, u := range users {
		byID[u.ID] = u
	}
	out := make([]AuditView, 0, len(rows))
	for _, r := range rows {
		v := AuditView{ID: r.ID, Timestamp: r.Timestamp, Action: r.Action, ActorType: r.ActorType,
			ResourceType: r.ResourceType, ResourceID: r.ResourceID, Status: string(r.Status), Level: string(r.Level),
			IPAddress: r.IPAddress, UserAgent: r.UserAgent, Details: r.Details}
		if v.Details == nil {
			v.Details = map[string]interface{}{}
		}
		if r.UserID != "" {
			a := &AuditActor{ID: r.UserID, Admin: r.ActorType == domain.AuditActorAdmin}
			if u := byID[r.UserID]; u != nil {
				a.Username = u.Username
			}
			v.Actor = a
		}
		if r.TargetUserID != "" {
			t := &AuditUserRef{ID: r.TargetUserID}
			if u := byID[r.TargetUserID]; u != nil {
				t.Username = u.Username
			} else if name, ok := r.Details["username"].(string); ok {
				t.Username = name // a deleted account (user.deleted keeps its name)
			}
			v.Target = t
		}
		out = append(out, v)
	}
	return out, nil
}

// AuditExportLimit caps one export: past it, the file says it is cut and
// the admin narrows the period.
const AuditExportLimit = 100_000

const auditExportPage = 200

// ExportAudit calls emit with every entry matching f, newest first, page
// by page (keyset paging: a long log costs the same per page). It stops
// after limit entries and reports whether more were left.
func (s *AdminService) ExportAudit(ctx context.Context, realm *domain.Realm, f repository.AuditSearch, limit int,
	emit func(AuditView) error) (n int, truncated bool, err error) {
	if limit <= 0 || limit > AuditExportLimit {
		limit = AuditExportLimit
	}
	f.RealmID = realm.ID
	f.Page = repository.Page{Limit: auditExportPage, NoTotal: true}
	f.Before = repository.AuditCursor{}
	for {
		rows, _, err := s.d.Admin.SearchAuditLogs(ctx, f)
		if err != nil {
			return n, false, err
		}
		views, err := s.auditViews(ctx, rows)
		if err != nil {
			return n, false, err
		}
		for _, v := range views {
			if n == limit {
				return n, true, nil
			}
			if err := emit(v); err != nil {
				return n, false, err
			}
			n++
		}
		if len(rows) < auditExportPage {
			return n, false, nil
		}
		last := rows[len(rows)-1]
		f.Before = repository.AuditCursor{Timestamp: last.Timestamp, ID: last.ID}
	}
}

// RecordAuditExport writes who exported the log, with which filters and
// how many entries left with the file.
func (s *AdminService) RecordAuditExport(ctx context.Context, actor AdminActor, realm *domain.Realm, format string,
	n int, truncated bool, filters map[string][]string) {
	f := map[string]interface{}{}
	for k, v := range filters {
		if k != "format" && len(v) > 0 && v[0] != "" {
			f[k] = v[0]
		}
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.AuditLogExported, "AuditLog", "", domain.AuditLogWarning, map[string]interface{}{
		"format": format, "entries": n, "truncated": truncated, "filters": f,
	})
}

// AuditActions is the catalogue of actions the filter offers.
func (s *AdminService) AuditActions() []audit.ActionInfo { return audit.Catalog }


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
	since := s.d.Now().Add(-24 * time.Hour)

	// Six independent reads, run at the same time: the screen waits for the
	// slowest one, not for their sum (each is one or two database round
	// trips, and a round trip through Docker's port forwarding is not free).
	// Each function writes its own fields of d.
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	run := func(f func() error) {
		wg.Go(func() {
			if err := f(); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		})
	}
	run(func() (err error) {
		d.ActiveSessions, err = s.countActiveSessions(ctx, realm)
		return err
	})
	run(func() (err error) {
		d.ActiveClients, err = s.d.Admin.CountActiveClients(ctx, realm.ID)
		return err
	})
	run(func() error {
		ok, ko, err := s.d.Admin.LoginCounts(ctx, realm.ID, since)
		d.Logins24h = LoginStats{Success: ok, Failure: ko, SuccessRate: -1}
		if ok+ko > 0 {
			d.Logins24h.SuccessRate = round1(100 * float64(ok) / float64(ok+ko))
		}
		return err
	})
	run(func() error {
		enrolled, users, err := s.d.Admin.MFACoverage(ctx, realm.ID)
		d.MFA = MFACoverage{Enrolled: enrolled, Total: users}
		if users > 0 {
			d.MFA.Percent = round1(100 * float64(enrolled) / float64(users))
		}
		return err
	})
	run(func() error {
		keys, err := s.d.KeyRotation.List(ctx, realm.ID)
		for _, k := range keys {
			if k.Status == domain.SigningKeyActive {
				d.SigningKeys = append(d.SigningKeys, SigningKeyInfo{Kid: k.Kid, KeyType: string(k.KeyType),
					Purpose: string(k.Purpose), Status: string(k.Status), CreatedAt: k.CreatedAt})
			}
		}
		return err
	})
	run(func() (err error) {
		// The dashboard shows no total: not counted.
		// Changes and security events, not the routine of every sign-in.
		d.RecentActivity, _, err = s.SearchAudit(ctx, realm, repository.AuditSearch{
			ExcludeActions: []string{audit.AuthLogin, audit.AuthLogout, audit.NotificationSent},
			Page:           repository.Page{Limit: 6, NoTotal: true},
		})
		return err
	})
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return d, nil
}

// activeWindow: a session is active when it has not expired and was used
// within the realm's idle timeout, with the same rules as the public
// server (SessionDurations.Limits) for remembered sessions.
func (s *AdminService) activeWindow(ctx context.Context, realm *domain.Realm) (repository.SessionSearch, error) {
	st, err := s.settingsOf(ctx, realm.ID)
	if err != nil {
		return repository.SessionSearch{}, err
	}
	d := SessionDurationsOf(st)
	now := s.d.Now()
	win := repository.SessionSearch{RealmID: realm.ID, Now: now, IdleSince: now.Add(-d.IdleTimeout)}
	if d.RememberMe {
		win.RememberIdleSince = now.Add(-d.RememberMeIdleTimeout)
	} else {
		win.RememberIdleSince = win.IdleSince
		win.RememberCreatedSince = now.Add(-d.MaxLifetime)
	}
	return win, nil
}

// countActiveSessions: the total of ListSessions, one COUNT query.
func (s *AdminService) countActiveSessions(ctx context.Context, realm *domain.Realm) (int, error) {
	win, err := s.activeWindow(ctx, realm)
	if err != nil {
		return 0, err
	}
	return s.d.Admin.CountSessions(ctx, win)
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }


// MFAPoliciesView: the MFA Policies screen.
type MFAPoliciesView struct {
	RequiredGlobally    bool             `json:"required_globally"`
	StepUpMaxAgeMinutes int              `json:"step_up_max_age_minutes"`
	Roles               []RolePolicyView `json:"roles"`
	Clients             []ClientPolicy   `json:"clients"`
	KnownMethods        []string         `json:"known_methods"`
	TrustedDevicesEnabled bool `json:"trusted_devices_enabled"`
	TrustedDeviceDays     int  `json:"trusted_device_days"`
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
		Roles: []RolePolicyView{}, Clients: []ClientPolicy{}, KnownMethods: methodNames(domain.KnownMfaMethodTypes),
		TrustedDevicesEnabled: ov.TrustedDevices, TrustedDeviceDays: ov.TrustedDeviceDays}
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

// RealmMFAInput: the realm-wide MFA settings (nil: unchanged).
type RealmMFAInput struct {
	Required          *bool
	StepUpMinutes     *int
	TrustedDevices    *bool
	TrustedDeviceDays *int
}

// SetRealmMFA changes the realm-wide policy.
func (s *AdminService) SetRealmMFA(ctx context.Context, actor AdminActor, realm *domain.Realm, in RealmMFAInput) (*MFAPoliciesView, error) {
	if isMaster(realm) && in.Required != nil && !*in.Required {
		return nil, adminRefused("system_realm", i18n.M("admin.error.mfa_master_required", "MFA stays required in the master realm"))
	}
	if isMaster(realm) && in.TrustedDevices != nil && *in.TrustedDevices {
		return nil, adminRefused("system_realm", i18n.M("admin.error.master_second_factor", "the master realm always asks for the second factor: its accounts administer the whole instance"))
	}
	var maxAge *time.Duration
	if in.StepUpMinutes != nil {
		d := time.Duration(*in.StepUpMinutes) * time.Minute
		maxAge = &d
	}
	if _, err := s.d.MFAPolicy.SetRealmPolicy(ctx, SetRealmMFAPolicyInput{RealmID: realm.ID, RequiredGlobally: in.Required,
		StepUpMaxAge: maxAge, TrustedDevices: in.TrustedDevices, TrustedDeviceDays: in.TrustedDeviceDays,
		Actor: PolicyActor{TriggeredBy: actor.By()}}); err != nil {
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



// SigningKeys lists every key of the realm (moved from the public server).
func (s *AdminService) SigningKeys(ctx context.Context, realm *domain.Realm) ([]*domain.SigningKey, error) {
	return s.d.KeyRotation.List(ctx, realm.ID)
}
