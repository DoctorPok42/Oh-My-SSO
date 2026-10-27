package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


var realmNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// RealmView is a realm in the realm switcher and on the realms page.
type RealmView struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	DisplayName string             `json:"display_name"`
	Status      domain.RealmStatus `json:"status"`
	System      bool               `json:"system"`
	CreatedAt   time.Time          `json:"created_at"`
}

func realmView(r *domain.Realm) RealmView {
	d := r.DisplayName
	if d == "" {
		d = r.Name
	}
	return RealmView{ID: r.ID, Name: r.Name, DisplayName: d, Status: r.Status, System: r.IsSystemRealm, CreatedAt: r.CreatedAt}
}

func (s *AdminService) ListRealms(ctx context.Context) ([]RealmView, error) {
	realms, err := s.d.Admin.ListRealms(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RealmView, 0, len(realms))
	for _, r := range realms {
		out = append(out, realmView(r))
	}
	return out, nil
}

func (s *AdminService) GetRealm(ctx context.Context, name string) (RealmView, error) {
	r, err := s.RealmByName(ctx, name)
	if err != nil {
		return RealmView{}, err
	}
	return realmView(r), nil
}

// CreateRealmInput: the "+ New realm" form.
type CreateRealmInput struct {
	Name        string
	DisplayName string
}

// CreateRealmResult: the realm, and a warning when it cannot sign tokens yet.
type CreateRealmResult struct {
	Realm   RealmView `json:"realm"`
	Warning string    `json:"warning,omitempty"`
}

// CreateRealm creates a realm with its settings and its signing keys (JWT
// for OIDC, RSA for SAML), ready to receive users and clients.
func (s *AdminService) CreateRealm(ctx context.Context, actor AdminActor, in CreateRealmInput) (*CreateRealmResult, error) {
	name := strings.TrimSpace(in.Name)
	if !realmNamePattern.MatchString(name) {
		return nil, adminInvalid("name", "realm name: 2-63 characters among a-z 0-9 and -, starting with a letter or digit")
	}
	display := strings.TrimSpace(in.DisplayName)
	if len(display) > 128 {
		return nil, adminInvalid("display_name", "display name: at most 128 characters")
	}
	if _, err := s.d.Realms.GetByName(ctx, name); err == nil {
		return nil, adminConflict("name_taken", "a realm named %q already exists", name)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	realm, err := s.d.Realms.Create(ctx, repository.CreateRealmParams{Name: name, DisplayName: display})
	if errors.Is(err, repository.ErrReservedRealmName) {
		return nil, adminInvalid("name", "%q is reserved (it collides with a route of the server)", name)
	}
	if err != nil {
		return nil, fmt.Errorf("create realm: %w", err)
	}
	if _, err := s.d.Settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: realm.ID}); err != nil {
		return nil, fmt.Errorf("create realm settings: %w", err)
	}
	res := &CreateRealmResult{Realm: realmView(realm)}
	warning, _, err := s.ensureSigningKey(ctx, realm.ID, actor.By())
	if err != nil {
		return nil, err
	}
	if warning == "" {
		_, err := s.d.KeyRotation.Rotate(ctx, RotateInput{RealmID: realm.ID, Purpose: domain.SigningKeyPurposeSAMLSigning,
			TriggeredBy: actor.By(), Reason: "realm setup"})
		if err != nil {
			return nil, fmt.Errorf("create SAML signing key: %w", err)
		}
	}
	res.Warning = warning

	details := map[string]interface{}{"name": name, "display_name": display}
	s.auditAdmin(ctx, actor, realm.ID, "realm.create", "Realm", realm.ID, domain.AuditLogWarning, details)
	// Instance-level action: the master realm keeps a trace too.
	s.auditAdmin(ctx, actor, actor.RealmID, "realm.create", "Realm", realm.ID, domain.AuditLogWarning, details)
	return res, nil
}

// UpdateRealmInput: nil fields are unchanged.
type UpdateRealmInput struct {
	DisplayName *string
	Status      *domain.RealmStatus
}

// UpdateRealm renames (display name) or enables/disables a realm. A
// disabled realm answers 404 everywhere on the public server; its users
// cannot sign in. The master realm cannot be disabled.
func (s *AdminService) UpdateRealm(ctx context.Context, actor AdminActor, name string, in UpdateRealmInput) (RealmView, error) {
	realm, err := s.RealmByName(ctx, name)
	if err != nil {
		return RealmView{}, err
	}
	params := repository.UpdateRealmParams{}
	details := map[string]interface{}{}
	if in.DisplayName != nil {
		d := strings.TrimSpace(*in.DisplayName)
		if len(d) > 128 {
			return RealmView{}, adminInvalid("display_name", "display name: at most 128 characters")
		}
		params.DisplayName = &d
		details["display_name"] = d
	}
	if in.Status != nil && *in.Status != realm.Status {
		switch *in.Status {
		case domain.RealmActive, domain.RealmInactive:
		default:
			return RealmView{}, adminInvalid("status", "status must be active or inactive")
		}
		if realm.IsSystemRealm {
			return RealmView{}, adminRefused("system_realm", "the master realm cannot be disabled: the admin console signs in through it")
		}
		params.Status = in.Status
		details["status"] = string(*in.Status)
	}
	if len(details) == 0 {
		return realmView(realm), nil
	}
	updated, err := s.d.Realms.Update(ctx, realm.ID, params)
	if err != nil {
		return RealmView{}, fmt.Errorf("update realm: %w", err)
	}
	level := domain.AuditLogInfo
	if params.Status != nil {
		level = domain.AuditLogWarning
	}
	s.auditAdmin(ctx, actor, realm.ID, "realm.update", "Realm", realm.ID, level, details)
	if realm.ID != actor.RealmID {
		s.auditAdmin(ctx, actor, actor.RealmID, "realm.update", "Realm", realm.ID, level, details)
	}
	return realmView(updated), nil
}

// --- settings -------------------------------------------------------------------

// SettingsView: the Settings screen. Every value, defaults included.
type SettingsView struct {
	ManagedBy                   string    `json:"managed_by"`
	MinPasswordLength           int       `json:"min_password_length"`
	PasswordExpiryDays          int       `json:"password_expiry_days"`
	PasswordResetTTLMinutes     int       `json:"password_reset_ttl_minutes"`
	SessionIdleMinutes          int       `json:"session_idle_minutes"`
	SessionMaxHours             int       `json:"session_max_hours"`
	RememberMeEnabled           bool      `json:"remember_me_enabled"`
	RememberMeIdleDays          int       `json:"remember_me_idle_days"`
	RememberMeMaxDays           int       `json:"remember_me_max_days"`
	LockoutThreshold            int       `json:"lockout_threshold"`
	LockoutDurationMinutes      int       `json:"lockout_duration_minutes"`
	IPAllowlist                 []string  `json:"ip_allowlist"`
	MFARequiredGlobally         bool      `json:"mfa_required_globally"`
	MFAStepUpMaxAgeMinutes      int       `json:"mfa_step_up_max_age_minutes"`
	KeyRotationGraceHours       int       `json:"key_rotation_grace_hours"`
	NotificationEmailEnabled    bool      `json:"notification_email_enabled"`
	SuspiciousLoginEmailEnabled bool      `json:"suspicious_login_email_enabled"`
	UpdatedAt                   time.Time `json:"updated_at"`
	UpdatedBy                   string    `json:"updated_by"`
}

func (s *AdminService) settingsOf(ctx context.Context, realmID string) (*domain.InstanceSettings, error) {
	st, err := s.d.Settings.GetByRealmID(ctx, realmID)
	if errors.Is(err, repository.ErrNotFound) {
		st = DefaultInstanceSettings(realmID)
		st.ManagedBy = domain.InstanceSettingsManagedByUI
		st.PasswordExpiryDays = 90
		st.KeyRotationGraceHours = 24
		st.MFAStepUpMaxAgeMinutes = 10
		return st, nil
	}
	return st, err
}

func (s *AdminService) GetSettings(ctx context.Context, realm *domain.Realm) (*SettingsView, error) {
	st, err := s.settingsOf(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	allow := st.IPAllowlist
	if allow == nil {
		allow = []string{}
	}
	return &SettingsView{
		ManagedBy: string(st.ManagedBy), MinPasswordLength: st.MinPasswordLength, PasswordExpiryDays: st.PasswordExpiryDays,
		PasswordResetTTLMinutes: st.PasswordResetTTLMinutes, SessionIdleMinutes: st.SessionIdleMinutes,
		SessionMaxHours: st.SessionMaxHours, RememberMeEnabled: st.RememberMeEnabled, RememberMeIdleDays: st.RememberMeIdleDays,
		RememberMeMaxDays: st.RememberMeMaxDays, LockoutThreshold: st.LockoutThreshold, LockoutDurationMinutes: st.LockoutDurationMinutes,
		IPAllowlist: allow, MFARequiredGlobally: st.MFARequiredGlobally, MFAStepUpMaxAgeMinutes: st.MFAStepUpMaxAgeMinutes,
		KeyRotationGraceHours: st.KeyRotationGraceHours, NotificationEmailEnabled: st.NotificationEmailEnabled,
		SuspiciousLoginEmailEnabled: st.SuspiciousLoginEmailEnabled, UpdatedAt: st.UpdatedAt, UpdatedBy: st.UpdatedBy,
	}, nil
}

// SettingsPatch: nil fields are unchanged.
type SettingsPatch struct {
	MinPasswordLength           *int
	PasswordExpiryDays          *int
	PasswordResetTTLMinutes     *int
	SessionIdleMinutes          *int
	SessionMaxHours             *int
	RememberMeEnabled           *bool
	RememberMeIdleDays          *int
	RememberMeMaxDays           *int
	LockoutThreshold            *int
	LockoutDurationMinutes      *int
	IPAllowlist                 *[]string
	MFARequiredGlobally         *bool
	MFAStepUpMaxAgeMinutes      *int
	KeyRotationGraceHours       *int
	NotificationEmailEnabled    *bool
	SuspiciousLoginEmailEnabled *bool
}

// UpdateSettings validates and applies a patch. Changes apply within a
// minute on the public server (its settings cache).
func (s *AdminService) UpdateSettings(ctx context.Context, actor AdminActor, realm *domain.Realm, p SettingsPatch) (*SettingsView, error) {
	rangeCheck := func(field string, v *int, lo, hi int) error {
		if v != nil && (*v < lo || *v > hi) {
			return adminInvalid(field, "%s must be between %d and %d", field, lo, hi)
		}
		return nil
	}
	for _, c := range []struct {
		field  string
		v      *int
		lo, hi int
	}{
		{"min_password_length", p.MinPasswordLength, 8, MaxPasswordLength},
		{"password_expiry_days", p.PasswordExpiryDays, 0, 3650},
		{"password_reset_ttl_minutes", p.PasswordResetTTLMinutes, 5, 24 * 60},
		{"session_idle_minutes", p.SessionIdleMinutes, 1, 7 * 24 * 60},
		{"session_max_hours", p.SessionMaxHours, 1, 90 * 24},
		{"remember_me_idle_days", p.RememberMeIdleDays, 1, maxRememberMeDays},
		{"remember_me_max_days", p.RememberMeMaxDays, 1, maxRememberMeDays},
		{"lockout_threshold", p.LockoutThreshold, 0, 100},
		{"lockout_duration_minutes", p.LockoutDurationMinutes, 1, 7 * 24 * 60},
		{"mfa_step_up_max_age_minutes", p.MFAStepUpMaxAgeMinutes, int(minMFAStepUpMaxAge / time.Minute), int(maxMFAStepUpMaxAge / time.Minute)},
		{"key_rotation_grace_hours", p.KeyRotationGraceHours, int(MinKeyRotationGrace / time.Hour), 365 * 24},
	} {
		if err := rangeCheck(c.field, c.v, c.lo, c.hi); err != nil {
			return nil, err
		}
	}
	var allow []string
	if p.IPAllowlist != nil {
		allow = []string{}
		for _, entry := range *p.IPAllowlist {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(entry); err != nil && net.ParseIP(entry) == nil {
				return nil, adminInvalid("ip_allowlist", "%q is neither an IP address nor a CIDR range", entry)
			}
			allow = append(allow, entry)
		}
	}
	if isMaster(realm) && p.MFARequiredGlobally != nil && !*p.MFARequiredGlobally {
		return nil, adminRefused("system_realm", "MFA stays required in the master realm: its accounts administer the whole instance")
	}

	st, err := s.d.Settings.GetByRealmID(ctx, realm.ID)
	if errors.Is(err, repository.ErrNotFound) {
		st, err = s.d.Settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: realm.ID})
	}
	if err != nil {
		return nil, err
	}
	if st.ManagedBy == domain.InstanceSettingsManagedByConfig {
		return nil, errManagedByConfig
	}
	merged := *st
	setIfNotNil(&merged.SessionIdleMinutes, p.SessionIdleMinutes)
	setIfNotNil(&merged.SessionMaxHours, p.SessionMaxHours)
	setIfNotNil(&merged.RememberMeEnabled, p.RememberMeEnabled)
	setIfNotNil(&merged.RememberMeIdleDays, p.RememberMeIdleDays)
	setIfNotNil(&merged.RememberMeMaxDays, p.RememberMeMaxDays)
	if err := ValidateSessionDurations(&merged); err != nil {
		return nil, err
	}
	by := actor.By()
	upd := repository.UpdateInstanceSettingsParams{
		MinPasswordLength: p.MinPasswordLength, PasswordExpiryDays: p.PasswordExpiryDays,
		PasswordResetTTLMinutes: p.PasswordResetTTLMinutes, SessionIdleMinutes: p.SessionIdleMinutes,
		SessionMaxHours: p.SessionMaxHours, RememberMeEnabled: p.RememberMeEnabled,
		RememberMeIdleDays: p.RememberMeIdleDays, RememberMeMaxDays: p.RememberMeMaxDays, LockoutThreshold: p.LockoutThreshold,
		LockoutDurationMinutes: p.LockoutDurationMinutes, IPAllowlist: allow,
		MFARequiredGlobally: p.MFARequiredGlobally, MFAStepUpMaxAgeMinutes: p.MFAStepUpMaxAgeMinutes,
		KeyRotationGraceHours: p.KeyRotationGraceHours, NotificationEmailEnabled: p.NotificationEmailEnabled,
		SuspiciousLoginEmailEnabled: p.SuspiciousLoginEmailEnabled, UpdatedBy: &by,
	}
	if _, err := s.d.Settings.Update(ctx, st.ID, upd); err != nil {
		return nil, fmt.Errorf("update settings: %w", err)
	}
	view, err := s.GetSettings(ctx, realm)
	if err != nil {
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "settings.update", "InstanceSettings", st.ID, domain.AuditLogWarning, settingsChanges(p))
	return view, nil
}

func settingsChanges(p SettingsPatch) map[string]interface{} {
	out := map[string]interface{}{}
	ints := map[string]*int{
		"min_password_length": p.MinPasswordLength, "password_expiry_days": p.PasswordExpiryDays,
		"password_reset_ttl_minutes": p.PasswordResetTTLMinutes, "session_idle_minutes": p.SessionIdleMinutes,
		"session_max_hours": p.SessionMaxHours, "remember_me_idle_days": p.RememberMeIdleDays,
		"remember_me_max_days": p.RememberMeMaxDays, "lockout_threshold": p.LockoutThreshold,
		"lockout_duration_minutes": p.LockoutDurationMinutes, "mfa_step_up_max_age_minutes": p.MFAStepUpMaxAgeMinutes,
		"key_rotation_grace_hours": p.KeyRotationGraceHours,
	}
	for k, v := range ints {
		if v != nil {
			out[k] = *v
		}
	}
	bools := map[string]*bool{
		"mfa_required_globally": p.MFARequiredGlobally, "notification_email_enabled": p.NotificationEmailEnabled,
		"suspicious_login_email_enabled": p.SuspiciousLoginEmailEnabled, "remember_me_enabled": p.RememberMeEnabled,
	}
	for k, v := range bools {
		if v != nil {
			out[k] = *v
		}
	}
	if p.IPAllowlist != nil {
		out["ip_allowlist"] = *p.IPAllowlist
	}
	return out
}

func setIfNotNil[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// ValidateSessionDurations checks the session durations of a realm as they
// will be saved. When "Keep me signed in" is on, a remembered session can
// neither stay idle longer than it lives, nor be shorter or end sooner
// when idle than a normal session (the option would then shorten
// sessions). Used by the Admin API and by `idp settings set`.
func ValidateSessionDurations(st *domain.InstanceSettings) error {
	if !st.RememberMeEnabled {
		return nil
	}
	d := SessionDurationsOf(st)
	const day = 24 * time.Hour
	switch {
	case d.RememberMeIdleTimeout > d.RememberMeMaxLifetime:
		return adminInvalid("remember_me_idle_days",
			"the idle timeout of a remembered session (%d days) cannot be longer than its maximum duration (%d days)",
			d.RememberMeIdleTimeout/day, d.RememberMeMaxLifetime/day)
	case d.RememberMeMaxLifetime < d.MaxLifetime:
		return adminInvalid("remember_me_max_days",
			"a remembered session (%d days) cannot be shorter than a normal session (%d hours)",
			d.RememberMeMaxLifetime/day, d.MaxLifetime/time.Hour)
	case d.RememberMeIdleTimeout < d.IdleTimeout:
		return adminInvalid("remember_me_idle_days",
			"the idle timeout of a remembered session (%d days) cannot be shorter than the one of a normal session (%d minutes)",
			d.RememberMeIdleTimeout/day, d.IdleTimeout/time.Minute)
	}
	return nil
}
