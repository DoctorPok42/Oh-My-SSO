package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


const (
	DefaultMFAStepUpMaxAge = 10 * time.Minute
	minMFAStepUpMaxAge     = time.Minute
	maxMFAStepUpMaxAge     = 24 * time.Hour
)

var (
	// ErrMFAPolicyConflict: two policies that both apply only accept
	// disjoint sets of methods (e.g. client "totp only", role "passkey
	// only"). Nobody could ever satisfy them: an admin must fix one.
	ErrMFAPolicyConflict = errors.New("service: mfa policies conflict (no method satisfies all of them)")
	ErrUnknownMFAMethod  = errors.New("service: unknown mfa method")
	ErrUnknownMFAPolicy  = errors.New("service: unknown client mfa policy")
	ErrManagedByConfig   = errors.New("service: resource is managed by the configuration file")
	ErrInvalidMFAPolicy  = errors.New("service: invalid mfa policy")
)

// MFARequirement is the outcome of the policy evaluation for one user, in
// one context (a client, or the IdP itself when Client is nil).
type MFARequirement struct {
	// Required: a verified second factor is mandatory right now.
	Required bool
	// AllowedMethods that satisfy the requirement. nil: any method.
	AllowedMethods []domain.MfaMethodType
	// EnrollmentDueAt is set when a role requires MFA but its grace period
	// is still running: not blocking yet, the user should enroll before.
	EnrollmentDueAt time.Time
	// StepUpForSensitiveActions: a role of the user demands a recent second
	// factor (not just a recent password login) for sensitive actions.
	StepUpForSensitiveActions bool
	// Sources explains the decision ("realm", "client:<id>", "role:<name>"),
	// for logs, the audit trail and the admin panel.
	Sources []string
}

// Allows tells whether a factor of type t satisfies the requirement.
func (r MFARequirement) Allows(t domain.MfaMethodType) bool {
	return r.AllowedMethods == nil || slices.Contains(r.AllowedMethods, t)
}

// mfaPolicyInput gathers everything the decision depends on.
type mfaPolicyInput struct {
	Settings      *domain.InstanceSettings // nil: realm defaults (nothing required)
	Client        *domain.ClientApp        // nil: login on the IdP itself
	RolePolicies  []*domain.MfaPolicy      // policies of the user's ACTIVE roles
	RoleNames     map[string]string        // role id -> name (for Sources)
	UserCreatedAt time.Time
	Now           time.Time
}

func resolveMFARequirement(in mfaPolicyInput) (MFARequirement, error) {
	var req MFARequirement
	var allowed []domain.MfaMethodType // nil = no restriction yet
	restricted := false

	restrict := func(methods []domain.MfaMethodType) {
		if len(methods) == 0 {
			return // empty list = any method: no restriction
		}
		if !restricted {
			allowed = slices.Clone(methods)
			restricted = true
			return
		}
		allowed = slices.DeleteFunc(allowed, func(m domain.MfaMethodType) bool {
			return !slices.Contains(methods, m)
		})
	}

	if in.Settings != nil && in.Settings.MFARequiredGlobally {
		req.Required = true
		req.Sources = append(req.Sources, "realm")
	}

	if c := in.Client; c != nil {
		if c.MFAPolicy == domain.ClientAppMFARequired {
			req.Required = true
			req.Sources = append(req.Sources, "client:"+clientLabel(c))
		}
		restrict(c.MFAAllowedMethods)
	}

	for _, p := range in.RolePolicies {
		name := in.RoleNames[p.RoleID]
		if name == "" {
			name = p.RoleID
		}
		restrict(p.AllowedMethods)
		if p.StepUpForSensitiveActions {
			req.StepUpForSensitiveActions = true
		}
		if !p.Required {
			continue
		}
		if due := enrollmentDeadline(p, in.UserCreatedAt); !due.IsZero() && in.Now.Before(due) {
			// Grace period still running: not required yet.
			if req.EnrollmentDueAt.IsZero() || due.Before(req.EnrollmentDueAt) {
				req.EnrollmentDueAt = due
			}
			continue
		}
		req.Required = true
		req.Sources = append(req.Sources, "role:"+name)
	}

	if restricted {
		if len(allowed) == 0 {
			return req, ErrMFAPolicyConflict
		}
		req.AllowedMethods = allowed
	}
	return req, nil
}

// enrollmentDeadline returns the end of the grace period of a role policy,
// or zero when there is none. The grace starts when the policy became
// required, or when the account was created if it is more recent.
//
// Known limit: the database does not record when a role was GIVEN to a user,
// so someone who gets the role long after the policy was enabled may find
// their grace period already over.
func enrollmentDeadline(p *domain.MfaPolicy, userCreatedAt time.Time) time.Time {
	if p.EnrollmentGraceDays <= 0 {
		return time.Time{}
	}
	start := p.RequiredSince
	if userCreatedAt.After(start) {
		start = userCreatedAt
	}
	if start.IsZero() {
		return time.Time{}
	}
	return start.Add(time.Duration(p.EnrollmentGraceDays) * 24 * time.Hour)
}

func clientLabel(c *domain.ClientApp) string {
	switch {
	case c.ClientID != "":
		return c.ClientID
	case c.EntityID != "":
		return c.EntityID
	default:
		return c.ID
	}
}

// ParseMFAMethods turns "totp,passkey" into a validated list. "", "any" and
// "*" mean "any method" (nil).
func ParseMFAMethods(s string) ([]domain.MfaMethodType, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "any" || s == "*" {
		return nil, nil
	}
	var out []domain.MfaMethodType
	for _, part := range strings.Split(s, ",") {
		m := domain.MfaMethodType(strings.TrimSpace(strings.ToLower(part)))
		if m == "" {
			continue
		}
		if m == "backup_code" {
			m = domain.MfaMethodBackupCodes
		}
		if !domain.IsKnownPolicyMethod(m) {
			return nil, fmt.Errorf("%w %q (expected: totp, passkey, webauthn, backup_codes)", ErrUnknownMFAMethod, m)
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

func validateMFAMethods(methods []domain.MfaMethodType) error {
	for _, m := range methods {
		if !domain.IsKnownPolicyMethod(m) {
			return fmt.Errorf("%w %q", ErrUnknownMFAMethod, m)
		}
	}
	return nil
}


type MFAPolicyService struct {
	settings repository.InstanceSettingsRepository
	clients  repository.ClientRepository
	roles    repository.RoleRepository
	policies repository.MfaPolicyRepository
	access   repository.AccessRepository
	audit    repository.AuditLogRepository // optional
	now      func() time.Time
}

type MFAPolicyDeps struct {
	Settings repository.InstanceSettingsRepository
	Clients  repository.ClientRepository
	Roles    repository.RoleRepository
	Policies repository.MfaPolicyRepository
	Access   repository.AccessRepository
	Audit    repository.AuditLogRepository // optional
	Now      func() time.Time              // optional
}

func NewMFAPolicyService(d MFAPolicyDeps) *MFAPolicyService {
	s := &MFAPolicyService{
		settings: d.Settings,
		clients:  d.Clients,
		roles:    d.Roles,
		policies: d.Policies,
		access:   d.Access,
		audit:    d.Audit,
		now:      d.Now,
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Requirement evaluates the policies for this user. client may be nil (login
// on the IdP itself, account console...).
func (s *MFAPolicyService) Requirement(ctx context.Context, user *domain.User, client *domain.ClientApp) (MFARequirement, error) {
	settings, err := s.realmSettings(ctx, user.RealmID)
	if err != nil {
		return MFARequirement{}, err
	}
	return s.requirementWith(ctx, user, client, settings)
}

// requirementWith is Requirement with the realm's settings already loaded.
func (s *MFAPolicyService) requirementWith(ctx context.Context, user *domain.User, client *domain.ClientApp, settings *domain.InstanceSettings) (MFARequirement, error) {
	var rolePolicies []*domain.MfaPolicy
	names := map[string]string{}
	if s.access != nil && s.policies != nil {
		access, err := s.access.GetUserAccess(ctx, user.ID)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return MFARequirement{}, fmt.Errorf("mfa policy: load user roles: %w", err)
		}
		if access != nil {
			ids := make([]string, 0, len(access.Roles))
			for _, r := range access.Roles {
				if !r.Active {
					continue // an inactive role grants nothing, and requires nothing
				}
				ids = append(ids, r.ID)
				names[r.ID] = r.Name
			}
			rolePolicies, err = s.policies.ListByRoleIDs(ctx, ids)
			if err != nil {
				return MFARequirement{}, fmt.Errorf("mfa policy: load role policies: %w", err)
			}
		}
	}

	return resolveMFARequirement(mfaPolicyInput{
		Settings:      settings,
		Client:        client,
		RolePolicies:  rolePolicies,
		RoleNames:     names,
		UserCreatedAt: user.CreatedAt,
		Now:           s.now(),
	})
}

// StepUpMaxAge is how long a second-factor verification counts as recent.
func (s *MFAPolicyService) StepUpMaxAge(ctx context.Context, realmID string) time.Duration {
	settings, err := s.realmSettings(ctx, realmID)
	if err != nil {
		return DefaultMFAStepUpMaxAge
	}
	return stepUpMaxAgeOf(settings)
}

// stepUpMaxAgeOf is StepUpMaxAge with the realm's settings already loaded
// (nil: none, the default).
func stepUpMaxAgeOf(settings *domain.InstanceSettings) time.Duration {
	if settings == nil || settings.MFAStepUpMaxAgeMinutes <= 0 {
		return DefaultMFAStepUpMaxAge
	}
	return time.Duration(settings.MFAStepUpMaxAgeMinutes) * time.Minute
}

func (s *MFAPolicyService) realmSettings(ctx context.Context, realmID string) (*domain.InstanceSettings, error) {
	if s.settings == nil {
		return nil, nil
	}
	settings, err := s.settings.GetByRealmID(ctx, realmID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mfa policy: load realm settings: %w", err)
	}
	return settings, nil
}


// Actor identifies who changes a policy, for the audit trail.
type PolicyActor struct {
	TriggeredBy string // "user:<id>", "cli:<os user>", "system:config-apply"
	// FromConfig is true only for the config-as-code reconciler: it is the
	// one allowed to change resources whose managed_by is "config".
	FromConfig bool
}

type SetRealmMFAPolicyInput struct {
	RealmID          string
	RequiredGlobally *bool
	StepUpMaxAge     *time.Duration
	Actor            PolicyActor
	// how many days (MinTrustedDeviceDays to MaxTrustedDeviceDays).
	TrustedDevices    *bool
	TrustedDeviceDays *int
}

// SetRealmPolicy changes the realm-wide settings, creating the realm's
// InstanceSettings row if it does not exist yet.
func (s *MFAPolicyService) SetRealmPolicy(ctx context.Context, in SetRealmMFAPolicyInput) (*domain.InstanceSettings, error) {
	var maxAge *int
	if in.StepUpMaxAge != nil {
		d := *in.StepUpMaxAge
		if d < minMFAStepUpMaxAge || d > maxMFAStepUpMaxAge {
			return nil, fmt.Errorf("%w: step-up max age must be between %s and %s", ErrInvalidMFAPolicy, minMFAStepUpMaxAge, maxMFAStepUpMaxAge)
		}
		m := int(d / time.Minute)
		maxAge = &m
	}
	if d := in.TrustedDeviceDays; d != nil && (*d < MinTrustedDeviceDays || *d > MaxTrustedDeviceDays) {
		return nil, fmt.Errorf("%w: trusted device days must be between %d and %d", ErrInvalidMFAPolicy, MinTrustedDeviceDays, MaxTrustedDeviceDays)
	}

	settings, err := s.settings.GetByRealmID(ctx, in.RealmID)
	if errors.Is(err, repository.ErrNotFound) {
		settings, err = s.settings.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: in.RealmID})
	}
	if err != nil {
		return nil, fmt.Errorf("set realm mfa policy: %w", err)
	}
	if settings.ManagedBy == domain.InstanceSettingsManagedByConfig && !in.Actor.FromConfig {
		return nil, ErrManagedByConfig
	}

	by := in.Actor.TriggeredBy
	updated, err := s.settings.Update(ctx, settings.ID, repository.UpdateInstanceSettingsParams{
		MFARequiredGlobally:     in.RequiredGlobally,
		MFAStepUpMaxAgeMinutes:  maxAge,
		MFATrustedDeviceEnabled: in.TrustedDevices,
		MFATrustedDeviceDays:    in.TrustedDeviceDays,
		UpdatedBy:               &by,
	})
	if err != nil {
		return nil, fmt.Errorf("set realm mfa policy: %w", err)
	}
	s.logPolicyChange(ctx, in.RealmID, "InstanceSettings", settings.ID, in.Actor, map[string]interface{}{
		"mfa_required_globally":       updated.MFARequiredGlobally,
		"mfa_step_up_max_age_minutes": updated.MFAStepUpMaxAgeMinutes,
		"mfa_trusted_device_enabled":  updated.MFATrustedDeviceEnabled,
		"mfa_trusted_device_days":     updated.MFATrustedDeviceDays,
	})
	return updated, nil
}

type SetClientMFAPolicyInput struct {
	RealmID   string
	ClientRef string // ClientApp.ID
	Policy    domain.ClientAppMFAPolicy
	// AllowedMethods: nil or empty = any method.
	AllowedMethods []domain.MfaMethodType
	Actor          PolicyActor
}

func (s *MFAPolicyService) SetClientPolicy(ctx context.Context, in SetClientMFAPolicyInput) (*domain.ClientApp, error) {
	switch in.Policy {
	case domain.ClientAppMFAInherit, domain.ClientAppMFARequired:
	default:
		return nil, fmt.Errorf("%w %q (expected: inherit, required)", ErrUnknownMFAPolicy, in.Policy)
	}
	if err := validateMFAMethods(in.AllowedMethods); err != nil {
		return nil, err
	}

	client, err := s.clients.GetByID(ctx, in.ClientRef)
	if err != nil {
		return nil, fmt.Errorf("set client mfa policy: %w", err)
	}
	if client.RealmID != in.RealmID {
		return nil, fmt.Errorf("set client mfa policy: %w", repository.ErrNotFound)
	}
	if client.ManagedBy == domain.ClientAppManagedByConfig && !in.Actor.FromConfig {
		return nil, ErrManagedByConfig
	}

	methods := in.AllowedMethods
	if methods == nil {
		methods = []domain.MfaMethodType{} // explicit "clear"
	}
	policy := in.Policy
	updated, err := s.clients.Update(ctx, client.ID, repository.UpdateClientAppParams{
		MFAPolicy:         &policy,
		MFAAllowedMethods: methods,
	})
	if err != nil {
		return nil, fmt.Errorf("set client mfa policy: %w", err)
	}
	s.logPolicyChange(ctx, in.RealmID, "ClientApp", client.ID, in.Actor, map[string]interface{}{
		"mfa_policy":          string(updated.MFAPolicy),
		"mfa_allowed_methods": methodNames(updated.MFAAllowedMethods),
	})
	return updated, nil
}

type SetRoleMFAPolicyInput struct {
	RealmID                   string
	RoleName                  string
	Required                  bool
	AllowedMethods            []domain.MfaMethodType // nil/empty: any
	EnrollmentGraceDays       int
	StepUpForSensitiveActions bool
	Actor                     PolicyActor
}

func (s *MFAPolicyService) SetRolePolicy(ctx context.Context, in SetRoleMFAPolicyInput) (*domain.MfaPolicy, error) {
	if err := validateMFAMethods(in.AllowedMethods); err != nil {
		return nil, err
	}
	if in.EnrollmentGraceDays < 0 || in.EnrollmentGraceDays > 365 {
		return nil, fmt.Errorf("%w: grace days must be between 0 and 365", ErrInvalidMFAPolicy)
	}
	role, err := s.roles.GetByRealmAndName(ctx, in.RealmID, in.RoleName)
	if err != nil {
		return nil, fmt.Errorf("set role mfa policy: role %q: %w", in.RoleName, err)
	}

	existing, err := s.policies.GetByRole(ctx, role.ID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("set role mfa policy: %w", err)
	}
	managedBy := domain.MfaPolicyManagedByUI
	if in.Actor.FromConfig {
		managedBy = domain.MfaPolicyManagedByConfig
	}
	var requiredSince time.Time
	if existing != nil {
		if existing.ManagedBy == domain.MfaPolicyManagedByConfig && !in.Actor.FromConfig {
			return nil, ErrManagedByConfig
		}
		managedBy = existing.ManagedBy
		if existing.Required {
			requiredSince = existing.RequiredSince // keep the running grace period
		}
	}
	if in.Required && requiredSince.IsZero() {
		requiredSince = s.now()
	}
	if !in.Required {
		requiredSince = time.Time{}
	}

	p, err := s.policies.Upsert(ctx, repository.UpsertMfaPolicyParams{
		RealmID:                   in.RealmID,
		RoleID:                    role.ID,
		ManagedBy:                 managedBy,
		Required:                  in.Required,
		AllowedMethods:            in.AllowedMethods,
		EnrollmentGraceDays:       in.EnrollmentGraceDays,
		StepUpForSensitiveActions: in.StepUpForSensitiveActions,
		RequiredSince:             requiredSince,
	})
	if err != nil {
		return nil, fmt.Errorf("set role mfa policy: %w", err)
	}
	s.logPolicyChange(ctx, in.RealmID, "MfaPolicy", p.ID, in.Actor, map[string]interface{}{
		"role":                          role.Name,
		"required":                      p.Required,
		"allowed_methods":               methodNames(p.AllowedMethods),
		"enrollment_grace_days":         p.EnrollmentGraceDays,
		"step_up_for_sensitive_actions": p.StepUpForSensitiveActions,
	})
	return p, nil
}

func (s *MFAPolicyService) DeleteRolePolicy(ctx context.Context, realmID, roleName string, actor PolicyActor) error {
	role, err := s.roles.GetByRealmAndName(ctx, realmID, roleName)
	if err != nil {
		return fmt.Errorf("delete role mfa policy: role %q: %w", roleName, err)
	}
	existing, err := s.policies.GetByRole(ctx, role.ID)
	if err != nil {
		return fmt.Errorf("delete role mfa policy: %w", err)
	}
	if existing.ManagedBy == domain.MfaPolicyManagedByConfig && !actor.FromConfig {
		return ErrManagedByConfig
	}
	if err := s.policies.DeleteByRole(ctx, role.ID); err != nil {
		return fmt.Errorf("delete role mfa policy: %w", err)
	}
	s.logPolicyChange(ctx, realmID, "MfaPolicy", existing.ID, actor, map[string]interface{}{
		"role": role.Name, "deleted": true,
	})
	return nil
}

// MFAPolicyOverview is everything that applies in a realm.
type MFAPolicyOverview struct {
	RequiredGlobally bool
	StepUpMaxAge     time.Duration
	Roles            []RoleMFAPolicyView
	Clients          []*domain.ClientApp // clients with a non-default policy
	// "Don't ask again on this device": offered, for how many days.
	TrustedDevices    bool
	TrustedDeviceDays int
}

type RoleMFAPolicyView struct {
	RoleName string
	Policy   *domain.MfaPolicy
}

func (s *MFAPolicyService) Overview(ctx context.Context, realmID string) (*MFAPolicyOverview, error) {
	out := &MFAPolicyOverview{StepUpMaxAge: s.StepUpMaxAge(ctx, realmID), TrustedDevices: true, TrustedDeviceDays: DefaultTrustedDeviceDays}
	settings, err := s.realmSettings(ctx, realmID)
	if err != nil {
		return nil, err
	}
	if settings != nil {
		out.RequiredGlobally = settings.MFARequiredGlobally
		out.TrustedDevices = settings.MFATrustedDeviceEnabled
		out.TrustedDeviceDays = clampTrustedDeviceDays(settings.MFATrustedDeviceDays)
	}

	policies, err := s.policies.ListByRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("mfa policy overview: %w", err)
	}
	for _, p := range policies {
		name := p.RoleID
		if r, err := s.roles.GetByID(ctx, p.RoleID); err == nil {
			name = r.Name
		}
		out.Roles = append(out.Roles, RoleMFAPolicyView{RoleName: name, Policy: p})
	}

	clients, err := s.clients.ListByRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("mfa policy overview: %w", err)
	}
	for _, c := range clients {
		if c.IsDeleted() {
			continue
		}
		if c.MFAPolicy == domain.ClientAppMFARequired || len(c.MFAAllowedMethods) > 0 {
			out.Clients = append(out.Clients, c)
		}
	}
	return out, nil
}

func (s *MFAPolicyService) logPolicyChange(ctx context.Context, realmID, resourceType, resourceID string, actor PolicyActor, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	details["triggered_by"] = actor.TriggeredBy
	_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      realmID,
		UserID:       userIDFromTrigger(actor.TriggeredBy),
		Action:       "mfa_policy_changed",
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Level:        domain.AuditLogWarning,
		Status:       domain.AuditLogSuccess,
		Details:      details,
	})
}

func userIDFromTrigger(triggeredBy string) string {
	if id, ok := strings.CutPrefix(triggeredBy, "user:"); ok {
		return id
	}
	return ""
}

func methodNames(in []domain.MfaMethodType) []string {
	out := make([]string, 0, len(in))
	for _, m := range in {
		out = append(out, string(m))
	}
	return out
}
