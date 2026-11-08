package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
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
		return nil, adminInvalid("name", i18n.M("admin.error.realm_name_bad", "realm name: 2-63 characters among a-z 0-9 and -, starting with a letter or digit"))
	}
	display := strings.TrimSpace(in.DisplayName)
	if len(display) > 128 {
		return nil, adminInvalid("display_name", i18n.M("admin.error.display_name_long", "display name: at most 128 characters"))
	}
	if _, err := s.d.Realms.GetByName(ctx, name); err == nil {
		return nil, adminConflict("name_taken", i18n.M("admin.error.realm_name_taken", "a realm named \"{name}\" already exists", "name", name))
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	realm, err := s.d.Realms.Create(ctx, repository.CreateRealmParams{Name: name, DisplayName: display})
	if errors.Is(err, repository.ErrReservedRealmName) {
		return nil, adminInvalid("name", i18n.M("admin.error.realm_name_reserved", "\"{name}\" is reserved (it collides with a route of the server)", "name", name))
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
	s.auditAdmin(ctx, actor, realm.ID, audit.RealmCreated, "Realm", realm.ID, domain.AuditLogWarning, details)
	// Instance-level action: the master realm keeps a trace too.
	s.auditAdmin(ctx, actor, actor.RealmID, audit.RealmCreated, "Realm", realm.ID, domain.AuditLogWarning, details)
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
			return RealmView{}, adminInvalid("display_name", i18n.M("admin.error.display_name_long", "display name: at most 128 characters"))
		}
		params.DisplayName = &d
		details["display_name"] = d
	}
	if in.Status != nil && *in.Status != realm.Status {
		switch *in.Status {
		case domain.RealmActive, domain.RealmInactive:
		default:
			return RealmView{}, adminInvalid("status", i18n.M("admin.error.realm_status", "status must be active or inactive"))
		}
		if realm.IsSystemRealm {
			return RealmView{}, adminRefused("system_realm", i18n.M("admin.error.master_disable", "the master realm cannot be disabled: the admin console signs in through it"))
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
	s.auditAdmin(ctx, actor, realm.ID, audit.RealmUpdated, "Realm", realm.ID, level, details)
	if realm.ID != actor.RealmID {
		s.auditAdmin(ctx, actor, actor.RealmID, audit.RealmUpdated, "Realm", realm.ID, level, details)
	}
	return realmView(updated), nil
}


// SettingsView: the Settings screen. Every value, defaults included.
type SettingsView struct {
	ManagedBy                   string    `json:"managed_by"`
	MinPasswordLength           int       `json:"min_password_length"`
	PasswordExpiryDays          int       `json:"password_expiry_days"`
	PasswordResetTTLMinutes     int       `json:"password_reset_ttl_minutes"`
	InviteTTLHours              int       `json:"invite_ttl_hours"`
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
	DefaultLocale               string    `json:"default_locale"`
	MailFromName                string    `json:"mail_from_name"`
	MailFromAddress             string    `json:"mail_from_address"`
	MailReplyTo                 string    `json:"mail_reply_to"`
	MailLogoURL                 string    `json:"mail_logo_url"`
	BulkLimit                   int       `json:"bulk_limit"`
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
		st.InviteTTLHours = defaultInviteTTLHours
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
		InviteTTLHours: st.InviteTTLHours, PasswordResetTTLMinutes: st.PasswordResetTTLMinutes, SessionIdleMinutes: st.SessionIdleMinutes,
		SessionMaxHours: st.SessionMaxHours, RememberMeEnabled: st.RememberMeEnabled, RememberMeIdleDays: st.RememberMeIdleDays,
		RememberMeMaxDays: st.RememberMeMaxDays, LockoutThreshold: st.LockoutThreshold, LockoutDurationMinutes: st.LockoutDurationMinutes,
		IPAllowlist: allow, MFARequiredGlobally: st.MFARequiredGlobally, MFAStepUpMaxAgeMinutes: st.MFAStepUpMaxAgeMinutes,
		KeyRotationGraceHours: st.KeyRotationGraceHours, NotificationEmailEnabled: st.NotificationEmailEnabled,
		SuspiciousLoginEmailEnabled: st.SuspiciousLoginEmailEnabled, DefaultLocale: localeOrEnglish(st.DefaultLocale),
		MailFromName: st.MailFromName, MailFromAddress: st.MailFromAddress, MailReplyTo: st.MailReplyTo, MailLogoURL: st.MailLogoURL, BulkLimit: effectiveBulkLimit(st),
		UpdatedAt: st.UpdatedAt, UpdatedBy: st.UpdatedBy,
	}, nil
}

// SettingsPatch: nil fields are unchanged.
type SettingsPatch struct {
	MinPasswordLength           *int
	PasswordExpiryDays          *int
	PasswordResetTTLMinutes     *int
	InviteTTLHours              *int
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
	DefaultLocale               *string
	MailFromName                *string
	MailFromAddress             *string
	MailReplyTo                 *string
	MailLogoURL                 *string
	BulkLimit                   *int
}

// UpdateSettings validates and applies a patch. Changes apply within a
// minute on the public server (its settings cache).
func (s *AdminService) UpdateSettings(ctx context.Context, actor AdminActor, realm *domain.Realm, p SettingsPatch) (*SettingsView, error) {
	rangeCheck := func(field string, v *int, lo, hi int) error {
		if v != nil && (*v < lo || *v > hi) {
			return adminInvalid(field, i18n.M("admin.error.range", "{field} must be between {lo} and {hi}", "field", field, "lo", lo, "hi", hi))
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
		{"invite_ttl_hours", p.InviteTTLHours, 1, 30 * 24},
		{"session_idle_minutes", p.SessionIdleMinutes, 1, 7 * 24 * 60},
		{"session_max_hours", p.SessionMaxHours, 1, 90 * 24},
		{"remember_me_idle_days", p.RememberMeIdleDays, 1, maxRememberMeDays},
		{"remember_me_max_days", p.RememberMeMaxDays, 1, maxRememberMeDays},
		{"lockout_threshold", p.LockoutThreshold, 0, 100},
		{"lockout_duration_minutes", p.LockoutDurationMinutes, 1, 7 * 24 * 60},
		{"mfa_step_up_max_age_minutes", p.MFAStepUpMaxAgeMinutes, int(minMFAStepUpMaxAge / time.Minute), int(maxMFAStepUpMaxAge / time.Minute)},
		{"key_rotation_grace_hours", p.KeyRotationGraceHours, int(MinKeyRotationGrace / time.Hour), 365 * 24},
		{"bulk_limit", p.BulkLimit, 1, MaxBulkLimit},
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
				return nil, adminInvalid("ip_allowlist", i18n.M("admin.error.ip_entry", "\"{entry}\" is neither an IP address nor a CIDR range", "entry", entry))
			}
			allow = append(allow, entry)
		}
	}
	if p.DefaultLocale != nil {
		lang := s.d.Languages.Match(*p.DefaultLocale)
		if lang == "" {
			return nil, adminInvalid("default_locale", i18n.M("admin.error.locale_unknown", "\"{locale}\" is not an available language", "locale", *p.DefaultLocale))
		}
		p.DefaultLocale = &lang
	}
	if err := normalizeMailSender(&p); err != nil {
		return nil, err
	}
	if isMaster(realm) && p.MFARequiredGlobally != nil && !*p.MFARequiredGlobally {
		return nil, adminRefused("system_realm", i18n.M("admin.error.mfa_master_full", "MFA stays required in the master realm: its accounts administer the whole instance"))
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
	if p.SessionIdleMinutes != nil && merged.MFAStepUpMaxAgeMinutes > merged.SessionIdleMinutes {
		return nil, adminInvalid("session_idle_minutes", i18n.M("admin.error.idle_vs_stepup", "the idle timeout ({idle} minutes) cannot be shorter than the MFA step-up window ({stepup} minutes): the session would end first and ask to sign in again", "idle", merged.SessionIdleMinutes, "stepup", merged.MFAStepUpMaxAgeMinutes))
	}
	by := actor.By()
	upd := repository.UpdateInstanceSettingsParams{
		MinPasswordLength: p.MinPasswordLength, PasswordExpiryDays: p.PasswordExpiryDays,
		InviteTTLHours: p.InviteTTLHours, PasswordResetTTLMinutes: p.PasswordResetTTLMinutes, SessionIdleMinutes: p.SessionIdleMinutes,
		SessionMaxHours: p.SessionMaxHours, RememberMeEnabled: p.RememberMeEnabled,
		RememberMeIdleDays: p.RememberMeIdleDays, RememberMeMaxDays: p.RememberMeMaxDays, LockoutThreshold: p.LockoutThreshold,
		LockoutDurationMinutes: p.LockoutDurationMinutes, IPAllowlist: allow,
		MFARequiredGlobally: p.MFARequiredGlobally, MFAStepUpMaxAgeMinutes: p.MFAStepUpMaxAgeMinutes,
		KeyRotationGraceHours: p.KeyRotationGraceHours, NotificationEmailEnabled: p.NotificationEmailEnabled,
		SuspiciousLoginEmailEnabled: p.SuspiciousLoginEmailEnabled, DefaultLocale: p.DefaultLocale, UpdatedBy: &by,
		MailFromName: p.MailFromName, MailFromAddress: p.MailFromAddress, MailReplyTo: p.MailReplyTo, MailLogoURL: p.MailLogoURL, BulkLimit: p.BulkLimit,
	}
	if _, err := s.d.Settings.Update(ctx, st.ID, upd); err != nil {
		return nil, fmt.Errorf("update settings: %w", err)
	}
	view, err := s.GetSettings(ctx, realm)
	if err != nil {
		return nil, err
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.SettingsUpdated, "InstanceSettings", st.ID, domain.AuditLogWarning, settingsChanges(p))
	return view, nil
}

func settingsChanges(p SettingsPatch) map[string]interface{} {
	out := map[string]interface{}{}
	ints := map[string]*int{
		"min_password_length": p.MinPasswordLength, "password_expiry_days": p.PasswordExpiryDays,
		"invite_ttl_hours": p.InviteTTLHours, "password_reset_ttl_minutes": p.PasswordResetTTLMinutes, "session_idle_minutes": p.SessionIdleMinutes,
		"session_max_hours": p.SessionMaxHours, "remember_me_idle_days": p.RememberMeIdleDays,
		"remember_me_max_days": p.RememberMeMaxDays, "lockout_threshold": p.LockoutThreshold,
		"lockout_duration_minutes": p.LockoutDurationMinutes, "mfa_step_up_max_age_minutes": p.MFAStepUpMaxAgeMinutes,
		"key_rotation_grace_hours": p.KeyRotationGraceHours, "bulk_limit": p.BulkLimit,
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
	if p.DefaultLocale != nil {
		out["default_locale"] = *p.DefaultLocale
	}
	for k, v := range map[string]*string{"mail_from_name": p.MailFromName, "mail_from_address": p.MailFromAddress, "mail_reply_to": p.MailReplyTo, "mail_logo_url": p.MailLogoURL} {
		if v != nil {
			out[k] = *v
		}
	}
	return out
}

// maxMailFromName / maxMailLogoURL bound what a realm can put in the headers
// and the layout of its e-mails.
const (
	maxMailFromName = 100
	maxMailLogoURL  = 2048
)

// normalizeMailSender trims and checks the sender settings of a patch. All
// four are optional ("" = the server's SMTP_FROM / no image).
//
//	mail_from_name     display name; no control character (a line break in a
//	                   header would let a value add headers)
//	mail_from_address  a plain address (no "Name <...>": the name has its own field)
//	mail_reply_to      same
//	mail_logo_url      https only: mail clients block http images, and an
//	                   http image leaks the opening of the e-mail
func normalizeMailSender(p *SettingsPatch) error {
	plainAddress := func(field string, v *string) error {
		if v == nil {
			return nil
		}
		*v = strings.TrimSpace(*v)
		if *v == "" {
			return nil
		}
		a, err := mail.ParseAddress(*v)
		if err != nil || a.Name != "" || a.Address != *v || strings.ContainsAny(*v, "\r\n") {
			return adminInvalid(field, i18n.M("admin.error.mail_address", "{field} must be a plain e-mail address such as noreply@example.com", "field", field))
		}
		return nil
	}
	if err := plainAddress("mail_from_address", p.MailFromAddress); err != nil {
		return err
	}
	if err := plainAddress("mail_reply_to", p.MailReplyTo); err != nil {
		return err
	}
	if v := p.MailFromName; v != nil {
		*v = strings.TrimSpace(*v)
		if len([]rune(*v)) > maxMailFromName || strings.IndexFunc(*v, unicode.IsControl) >= 0 {
			return adminInvalid("mail_from_name", i18n.M("admin.error.mail_from_name", "the sender name must be at most {max} characters, without line breaks", "max", maxMailFromName))
		}
	}
	if v := p.MailLogoURL; v != nil {
		*v = strings.TrimSpace(*v)
		if *v != "" {
			u, err := url.Parse(*v)
			if err != nil || u.Scheme != "https" || u.Host == "" || len(*v) > maxMailLogoURL {
				return adminInvalid("mail_logo_url", i18n.M("admin.error.mail_logo_url", "the image must be an https:// address of at most {max} characters", "max", maxMailLogoURL))
			}
		}
	}
	return nil
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
		return adminInvalid("remember_me_idle_days", i18n.M("admin.error.remember_idle_gt_max", "the idle timeout of a remembered session ({idle} days) cannot be longer than its maximum duration ({max} days)", "idle", d.RememberMeIdleTimeout/day, "max", d.RememberMeMaxLifetime/day))
	case d.RememberMeMaxLifetime < d.MaxLifetime:
		return adminInvalid("remember_me_max_days", i18n.M("admin.error.remember_max_lt_normal", "a remembered session ({days} days) cannot be shorter than a normal session ({hours} hours)", "days", d.RememberMeMaxLifetime/day, "hours", d.MaxLifetime/time.Hour))
	case d.RememberMeIdleTimeout < d.IdleTimeout:
		return adminInvalid("remember_me_idle_days", i18n.M("admin.error.remember_idle_lt_normal", "the idle timeout of a remembered session ({days} days) cannot be shorter than the one of a normal session ({minutes} minutes)", "days", d.RememberMeIdleTimeout/day, "minutes", d.IdleTimeout/time.Minute))
	}
	return nil
}

// localeOrEnglish: a settings row older than default_locale reads "".
func localeOrEnglish(tag string) string {
	if tag == "" {
		return i18n.English
	}
	return tag
}

// Languages lists the languages the IdP can show, English first.
func (s *AdminService) Languages() []i18n.Language { return s.d.Languages.Languages() }
