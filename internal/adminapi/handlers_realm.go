package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

// --- me -------------------------------------------------------------------------

type meResponse struct {
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Name     string `json:"name"`
	} `json:"user"`
	// Permissions: "client:write", ... The console hides what is not allowed;
	// the API checks again anyway.
	Permissions []string `json:"permissions"`
	// StepUpFreshUntil: until when changes need no new second factor.
	StepUpFreshUntil *time.Time `json:"step_up_fresh_until"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	a := adminFrom(r)
	var out meResponse
	out.User.ID, out.User.Username, out.User.Email = a.user.ID, a.user.Username, a.user.Email
	out.User.Name = a.user.Username
	if n, ok := a.user.Profile["name"].(string); ok && n != "" {
		out.User.Name = n
	} else if g, ok := a.user.Profile["given_name"].(string); ok && g != "" {
		f, _ := a.user.Profile["family_name"].(string)
		out.User.Name = strings.TrimSpace(g + " " + f)
	}
	perms := []string{}
	for _, p := range service.AdminPermissions {
		err := s.d.RBAC.Authorize(r.Context(), service.AuthorizeInput{RealmID: a.master.ID, UserID: a.user.ID,
			ClientRef: a.client.ID, Resource: p.Resource, Action: p.Action})
		if err == nil {
			perms = append(perms, p.Name())
		}
	}
	out.Permissions = perms
	if err := s.d.MFA.CheckStepUp(r.Context(), a.session, service.StepUpSensitiveAction); err == nil && !a.session.MFAVerifiedAt.IsZero() {
		t := a.session.MFAVerifiedAt.Add(s.stepUpWindow(r.Context(), a))
		out.StepUpFreshUntil = &t
	}
	writeJSON(w, http.StatusOK, out)
}

// stepUpWindow: the master realm's step-up max age.
func (s *Server) stepUpWindow(ctx context.Context, a *adminContext) time.Duration {
	view, err := s.d.Admin.MFAPolicies(ctx, a.master)
	if err != nil || view.StepUpMaxAgeMinutes <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(view.StepUpMaxAgeMinutes) * time.Minute
}

// --- realms ---------------------------------------------------------------------

func (s *Server) handleListRealms(w http.ResponseWriter, r *http.Request) {
	realms, err := s.d.Admin.ListRealms(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.RealmView]{Items: items(realms), Total: len(realms), Limit: len(realms)})
}

func (s *Server) handleCreateRealm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := s.d.Admin.CreateRealm(r.Context(), adminFrom(r).actor, service.CreateRealmInput{Name: in.Name, DisplayName: in.DisplayName})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

type realmDetail struct {
	service.RealmView
	Issuer       string `json:"issuer"`
	JWKSURL      string `json:"jwks_url"`
	SAMLMetadata string `json:"saml_metadata_url"`
}

func (s *Server) realmDetail(v service.RealmView) realmDetail {
	base := trimSlash(s.cfg.PublicURL) + "/r/" + v.Name
	return realmDetail{RealmView: v, Issuer: base, JWKSURL: base + "/.well-known/jwks.json", SAMLMetadata: base + "/saml/metadata"}
}

func (s *Server) handleGetRealm(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.GetRealm(r.Context(), realmFrom(r).Name)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.realmDetail(v))
}

func (s *Server) handleUpdateRealm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DisplayName *string `json:"display_name"`
		Status      *string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	upd := service.UpdateRealmInput{DisplayName: in.DisplayName}
	if in.Status != nil {
		st := domain.RealmStatus(*in.Status)
		upd.Status = &st
	}
	v, err := s.d.Admin.UpdateRealm(r.Context(), adminFrom(r).actor, realmFrom(r).Name, upd)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.realmDetail(v))
}

// --- dashboard ------------------------------------------------------------------

// ErrDisabled: a health check of something not configured (e.g. SMTP).
var ErrDisabled = errors.New("disabled")

type healthLine struct {
	Name      string `json:"name"`
	Status    string `json:"status"` // healthy | down | disabled
	Detail    string `json:"detail,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
}

type dashboardResponse struct {
	*service.Dashboard
	Infrastructure []healthLine `json:"infrastructure"`
	Realm          realmDetail  `json:"realm"`
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	realm := realmFrom(r)
	d, err := s.d.Admin.Dashboard(r.Context(), realm)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dashboardResponse{Dashboard: d, Infrastructure: s.health(r.Context()),
		Realm: s.realmDetail(mustRealmView(realm))})
}

func mustRealmView(r *domain.Realm) service.RealmView {
	d := r.DisplayName
	if d == "" {
		d = r.Name
	}
	return service.RealmView{ID: r.ID, Name: r.Name, DisplayName: d, Status: r.Status, System: r.IsSystemRealm, CreatedAt: r.CreatedAt}
}

// health runs every check at once, 3 seconds at most each.
func (s *Server) health(ctx context.Context) []healthLine {
	out := make([]healthLine, len(s.d.Health))
	var wg sync.WaitGroup
	for i, h := range s.d.Health {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			start := time.Now()
			err := h.Check(cctx)
			line := healthLine{Name: h.Name, Status: "healthy", LatencyMS: time.Since(start).Milliseconds()}
			switch {
			case errors.Is(err, ErrDisabled):
				line.Status, line.LatencyMS = "disabled", 0
			case err != nil:
				line.Status, line.Detail = "down", err.Error()
			}
			out[i] = line
		})
	}
	wg.Wait()
	return out
}

// --- signing keys (moved from the public server, Step 8 / 11) ------------------

type keyView struct {
	Kid         string     `json:"kid"`
	KeyType     string     `json:"key_type"`
	Algorithm   string     `json:"algorithm"`
	Purpose     string     `json:"purpose"`
	Status      string     `json:"status"`
	KMSBackend  string     `json:"kms_backend"`
	CreatedAt   time.Time  `json:"created_at"`
	RetireAfter *time.Time `json:"retire_after,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

// toKeyView: never kms_key_reference (internal pointer into the KMS).
func toKeyView(k *domain.SigningKey) keyView {
	v := keyView{Kid: k.Kid, KeyType: string(k.KeyType), Purpose: string(k.Purpose), Status: string(k.Status),
		KMSBackend: k.KMSBackend, CreatedAt: k.CreatedAt, Algorithm: "RS256"}
	if k.KeyType == domain.SigningKeyEC {
		v.Algorithm = "ES256"
	}
	if !k.RetireAfter.IsZero() {
		t := k.RetireAfter
		v.RetireAfter = &t
	}
	if !k.RetiredAt.IsZero() {
		t := k.RetiredAt
		v.RetiredAt = &t
	}
	return v
}

func toKeyViews(keys []*domain.SigningKey) []keyView {
	out := make([]keyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, toKeyView(k))
	}
	return out
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	realm := realmFrom(r)
	keys, err := s.d.Admin.SigningKeys(r.Context(), realm)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	d := s.realmDetail(mustRealmView(realm))
	writeJSON(w, http.StatusOK, map[string]any{"keys": toKeyViews(keys), "jwks_url": d.JWKSURL, "saml_metadata_url": d.SAMLMetadata})
}

type rotateKeyResponse struct {
	NewKey     keyView   `json:"new_key"`
	Rotating   []keyView `json:"rotating"`
	Retired    []keyView `json:"retired"`
	GraceHours float64   `json:"grace_hours"`
	Warning    string    `json:"warning,omitempty"`
}

func rotationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, service.ErrGraceTooShort):
		writeError(w, http.StatusBadRequest, "grace_too_short", err.Error())
	case errors.Is(err, service.ErrCompromisedReasonRequired):
		writeError(w, http.StatusBadRequest, "reason_required", "a reason is required when the key is compromised")
	case errors.Is(err, service.ErrUnsupportedRotationPurpose), errors.Is(err, service.ErrActivationNotSupported):
		writeError(w, http.StatusBadRequest, "unsupported_purpose", err.Error())
	case errors.Is(err, service.ErrSAMLKeyMustBeRSA):
		writeError(w, http.StatusBadRequest, "unsupported_key_type", "SAML keys must be RSA")
	case errors.Is(err, service.ErrPendingKeyExists):
		writeError(w, http.StatusConflict, "pending_key_exists", "a new SAML key is already waiting: activate it first")
	case errors.Is(err, service.ErrNoPendingKey):
		writeError(w, http.StatusConflict, "no_pending_key", "there is no pending key to activate")
	default:
		writeServiceError(w, r, err)
	}
}

// refuseLocalDevKeys: see Config.KMSBackend.
func (s *Server) refuseLocalDevKeys(w http.ResponseWriter) bool {
	if s.cfg.KMSBackend != "local_dev" {
		return false
	}
	writeError(w, http.StatusConflict, "local_dev_keys", "KEYMANAGER_BACKEND=local_dev keeps private keys in the memory of one "+
		"process: a key created by the Admin API could never sign on the public server. Use Vault (`make dev`).")
	return true
}

func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if s.refuseLocalDevKeys(w) {
		return
	}
	var in struct {
		Purpose     string `json:"purpose"`  // jwt_signing (default) | saml_signing
		KeyType     string `json:"key_type"` // RSA | EC | "" (same as now)
		GraceHours  int    `json:"grace_hours"`
		Compromised bool   `json:"compromised"`
		Reason      string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.GraceHours < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "grace_hours cannot be negative")
		return
	}
	switch domain.SigningKeyType(in.KeyType) {
	case "", domain.SigningKeyRSA, domain.SigningKeyEC:
	default:
		writeError(w, http.StatusBadRequest, "unsupported_key_type", "key_type must be RSA or EC")
		return
	}
	purpose := domain.SigningKeyPurposeJWT
	if in.Purpose != "" {
		purpose = domain.SigningKeyPurpose(in.Purpose)
	}
	a, realm := adminFrom(r), realmFrom(r)
	res, err := s.d.KeyRotation.Rotate(r.Context(), service.RotateInput{RealmID: realm.ID, Purpose: purpose,
		KeyType: domain.SigningKeyType(in.KeyType), Grace: time.Duration(in.GraceHours) * time.Hour,
		Compromised: in.Compromised, TriggeredBy: a.actor.By(), Reason: in.Reason})
	s.writeRotation(w, r, res, err)
}

func (s *Server) handleActivateKey(w http.ResponseWriter, r *http.Request) {
	if s.refuseLocalDevKeys(w) {
		return
	}
	var in struct {
		Purpose    string `json:"purpose"` // default saml_signing
		GraceHours int    `json:"grace_hours"`
		Reason     string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	purpose := domain.SigningKeyPurposeSAMLSigning
	if in.Purpose != "" {
		purpose = domain.SigningKeyPurpose(in.Purpose)
	}
	a, realm := adminFrom(r), realmFrom(r)
	res, err := s.d.KeyRotation.Activate(r.Context(), service.ActivateInput{RealmID: realm.ID, Purpose: purpose,
		Grace: time.Duration(in.GraceHours) * time.Hour, TriggeredBy: a.actor.By(), Reason: in.Reason})
	s.writeRotation(w, r, res, err)
}

func (s *Server) writeRotation(w http.ResponseWriter, r *http.Request, res *service.RotateResult, err error) {
	if res == nil || res.NewKey == nil {
		rotationError(w, r, err)
		return
	}
	out := rotateKeyResponse{NewKey: toKeyView(res.NewKey), Rotating: toKeyViews(res.Rotating),
		Retired: toKeyViews(res.Retired), GraceHours: res.Grace.Hours()}
	if err != nil {
		// The new key works; a follow-up step failed (e.g. a log write).
		out.Warning = "the new key is in place, but some follow-up steps failed: check the server logs"
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRetireKeys(w http.ResponseWriter, r *http.Request) {
	a, realm := adminFrom(r), realmFrom(r)
	retired, err := s.d.KeyRotation.RetireExpired(r.Context(), realm.ID, a.actor.By())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": toKeyViews(retired)})
}

// --- MFA policies ---------------------------------------------------------------

func (s *Server) handleMFAPolicies(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.MFAPolicies(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSetRealmMFA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Required            *bool `json:"required_globally"`
		StepUpMaxAgeMinutes *int  `json:"step_up_max_age_minutes"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.SetRealmMFA(r.Context(), adminFrom(r).actor, realmFrom(r), in.Required, in.StepUpMaxAgeMinutes)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSetRoleMFA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Required                  bool     `json:"required"`
		AllowedMethods            []string `json:"allowed_methods"`
		EnrollmentGraceDays       int      `json:"enrollment_grace_days"`
		StepUpForSensitiveActions bool     `json:"step_up_for_sensitive_actions"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.SetRoleMFA(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), service.RolePolicyInput{
		Required: in.Required, AllowedMethods: in.AllowedMethods, EnrollmentGraceDays: in.EnrollmentGraceDays,
		StepUpForSensitiveActions: in.StepUpForSensitiveActions})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteRoleMFA(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.DeleteRoleMFA(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// --- settings -------------------------------------------------------------------

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.GetSettings(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse{SettingsView: v, EmailEnabled: s.d.TestEmail != nil})
}

type settingsResponse struct {
	*service.SettingsView
	// EmailEnabled: e-mails can leave the server (SMTP configured).
	EmailEnabled bool `json:"email_enabled"`
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MinPasswordLength           *int      `json:"min_password_length"`
		PasswordExpiryDays          *int      `json:"password_expiry_days"`
		PasswordResetTTLMinutes     *int      `json:"password_reset_ttl_minutes"`
		SessionIdleMinutes          *int      `json:"session_idle_minutes"`
		SessionMaxHours             *int      `json:"session_max_hours"`
		LockoutThreshold            *int      `json:"lockout_threshold"`
		LockoutDurationMinutes      *int      `json:"lockout_duration_minutes"`
		IPAllowlist                 *[]string `json:"ip_allowlist"`
		MFARequiredGlobally         *bool     `json:"mfa_required_globally"`
		MFAStepUpMaxAgeMinutes      *int      `json:"mfa_step_up_max_age_minutes"`
		KeyRotationGraceHours       *int      `json:"key_rotation_grace_hours"`
		NotificationEmailEnabled    *bool     `json:"notification_email_enabled"`
		SuspiciousLoginEmailEnabled *bool     `json:"suspicious_login_email_enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.UpdateSettings(r.Context(), adminFrom(r).actor, realmFrom(r), service.SettingsPatch(in))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse{SettingsView: v, EmailEnabled: s.d.TestEmail != nil})
}

func (s *Server) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		To string `json:"to"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.d.TestEmail == nil {
		writeError(w, http.StatusConflict, "email_disabled", "e-mail is not configured on the server (SMTP_HOST)")
		return
	}
	addr, err := mail.ParseAddress(strings.TrimSpace(in.To))
	if err != nil || addr.Name != "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request", Message: "a plain e-mail address is required", Field: "to"})
		return
	}
	if err := s.d.TestEmail(r.Context(), addr.Address); err != nil {
		writeError(w, http.StatusBadGateway, "email_failed", "the mail server refused or did not answer: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent", "to": addr.Address})
}

// --- timeouts -------------------------------------------------------------------

func (s *Server) handleTimeouts(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.ListTimeouts(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.TimeoutView]{Items: items(v), Total: len(v), Limit: len(v)})
}
