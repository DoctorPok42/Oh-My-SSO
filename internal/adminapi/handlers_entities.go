package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/notify"
)

// --- clients --------------------------------------------------------------------

type scopeChoiceJSON struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

type certificateJSON struct {
	PEM       string     `json:"pem"`
	NotBefore *time.Time `json:"not_before"`
	NotAfter  *time.Time `json:"not_after"`
}

func (c certificateJSON) domain() domain.ClientCertificate {
	out := domain.ClientCertificate{PEM: c.PEM}
	if c.NotBefore != nil {
		out.NotBefore = *c.NotBefore
	}
	if c.NotAfter != nil {
		out.NotAfter = *c.NotAfter
	}
	return out
}

// clientJSON is the body of POST/PATCH /clients. Absent fields are left
// unchanged (PATCH) or take their default (POST).
type clientJSON struct {
	Protocol string  `json:"protocol"` // POST only: oidc | saml2
	Name     *string `json:"name"`
	Active   *bool   `json:"active"`

	ClientID                *string   `json:"client_id"` // POST only; empty: generated
	Public                  *bool     `json:"public"`    // POST only
	RedirectURIs            *[]string `json:"redirect_uris"`
	PostLogoutRedirectURIs  *[]string `json:"post_logout_redirect_uris"`
	StandardScopes          *[]string `json:"standard_scopes"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method"`
	RequirePKCE             *bool     `json:"require_pkce"`
	AccessTokenTTL          *int      `json:"access_token_ttl"`
	RefreshTokenTTL         *int      `json:"refresh_token_ttl"`
	IDTokenTTL              *int      `json:"id_token_ttl"`

	EntityID           *string           `json:"entity_id"`
	ACSURL             *string           `json:"acs_url"`
	SLOURL             *string           `json:"slo_url"`
	NameIDFormat       *string           `json:"name_id_format"`
	WantResponseSigned *bool             `json:"want_response_signed"`
	DefaultRelayState  *string           `json:"default_relay_state"`
	Pairwise           *bool             `json:"pairwise"`     // POST only
	Certificates       []certificateJSON `json:"certificates"` // POST only

	ClientScopes    *[]scopeChoiceJSON `json:"client_scopes"`
	AllowedRoleIDs  *[]string          `json:"allowed_role_ids"`
	AllowedGroupIDs *[]string          `json:"allowed_group_ids"`
	RequireConsent  *bool              `json:"require_consent"`
	MFAPolicy       *string            `json:"mfa_policy"`
	MFAMethods      *[]string          `json:"mfa_methods"`
}

func (c clientJSON) input() service.ClientInput {
	in := service.ClientInput{
		Protocol: domain.ClientAppProtocol(c.Protocol), Name: c.Name, Active: c.Active,
		ClientID: c.ClientID, Public: c.Public, RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		StandardScopes: c.StandardScopes, TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, RequirePKCE: c.RequirePKCE,
		AccessTokenTTL: c.AccessTokenTTL, RefreshTokenTTL: c.RefreshTokenTTL, IDTokenTTL: c.IDTokenTTL,
		EntityID: c.EntityID, ACSURL: c.ACSURL, SLOURL: c.SLOURL, NameIDFormat: c.NameIDFormat,
		WantResponseSigned: c.WantResponseSigned, DefaultRelayState: c.DefaultRelayState, Pairwise: c.Pairwise,
		AllowedRoleIDs: c.AllowedRoleIDs, AllowedGroupIDs: c.AllowedGroupIDs, RequireConsent: c.RequireConsent,
		MFAPolicy: c.MFAPolicy, MFAMethods: c.MFAMethods,
	}
	for _, cert := range c.Certificates {
		in.Certificates = append(in.Certificates, cert.domain())
	}
	if c.ClientScopes != nil {
		choices := make([]service.ScopeChoiceInput, 0, len(*c.ClientScopes))
		for _, ch := range *c.ClientScopes {
			choices = append(choices, service.ScopeChoiceInput{ID: ch.ID, Required: ch.Required})
		}
		in.ClientScopes = &choices
	}
	return in
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	protocol := domain.ClientAppProtocol(r.URL.Query().Get("protocol"))
	switch protocol {
	case "", domain.ClientAppProtocolOIDC, domain.ClientAppProtocolSAML2:
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "protocol must be oidc or saml2")
		return
	}
	all, err := s.d.Admin.ListClients(r.Context(), realmFrom(r), protocol)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	p := page(r)
	writeJSON(w, http.StatusOK, list[service.ClientSummary]{Items: items(paginate(all, p)), Total: len(all), Offset: p.Offset, Limit: p.Limit})
}

func paginate[T any](all []T, p repository.Page) []T {
	if p.Offset >= len(all) {
		return []T{}
	}
	end := p.Offset + p.Limit
	if end > len(all) {
		end = len(all)
	}
	return all[p.Offset:end]
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var in clientJSON
	if !decode(w, r, &in) {
		return
	}
	res, err := s.d.Admin.CreateClient(r.Context(), adminFrom(r).actor, realmFrom(r), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.GetClient(r.Context(), realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var in clientJSON
	if !decode(w, r, &in) {
		return
	}
	if in.Protocol != "" || in.ClientID != nil || in.Public != nil || in.Pairwise != nil || in.Certificates != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"protocol, client_id, public, pairwise and certificates cannot change here (certificates: use /certificates)")
		return
	}
	v, err := s.d.Admin.UpdateClient(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.DeleteClient(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	secret, err := s.d.Admin.RotateClientSecret(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (s *Server) handleAddCertificate(w http.ResponseWriter, r *http.Request) {
	var in certificateJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.AddClientCertificate(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.domain())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleRemoveCertificate(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.RemoveClientCertificate(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), chi.URLParam(r, "fingerprint"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// --- client scopes --------------------------------------------------------------

type scopeJSON struct {
	Name        *string                `json:"name"`
	Description *string                `json:"description"`
	Protocol    *string                `json:"protocol"`
	IsDefault   *bool                  `json:"is_default"`
	Mappers     *[]service.ClaimMapper `json:"claim_mappers"`
}

func (j scopeJSON) input() service.ClientScopeInput {
	return service.ClientScopeInput{Name: j.Name, Description: j.Description, Protocol: j.Protocol, IsDefault: j.IsDefault, Mappers: j.Mappers}
}

func (s *Server) handleListScopes(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.ListClientScopes(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.ClientScopeView]{Items: items(v), Total: len(v), Limit: len(v)})
}

func (s *Server) handleCreateScope(w http.ResponseWriter, r *http.Request) {
	var in scopeJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.CreateClientScope(r.Context(), adminFrom(r).actor, realmFrom(r), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleGetScope(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.GetClientScope(r.Context(), realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleUpdateScope(w http.ResponseWriter, r *http.Request) {
	var in scopeJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.UpdateClientScope(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteScope(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.DeleteClientScope(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- sessions, audit ------------------------------------------------------------

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	p := page(r)
	q := r.URL.Query()
	v, total, err := s.d.Admin.ListSessions(r.Context(), realmFrom(r), service.SessionFilter{UserID: q.Get("user"), ClientRef: q.Get("client"), Page: p})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	for i := range v {
		v[i].Device = notify.DescribeUserAgent(v[i].UserAgent)
	}
	writeJSON(w, http.StatusOK, list[service.SessionView]{Items: items(v), Total: total, Offset: p.Offset, Limit: p.Limit})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.RevokeSession(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	p := page(r)
	q := r.URL.Query()
	from, ok1 := timeParam(r, "from")
	to, ok2 := timeParam(r, "to")
	if !ok1 || !ok2 {
		writeError(w, http.StatusBadRequest, "invalid_request", "from / to: RFC 3339 time or YYYY-MM-DD")
		return
	}
	if len(q.Get("to")) == len("2006-01-02") {
		to = to.Add(24 * time.Hour) // a date means "this whole day"
	}
	status := domain.AuditLogStatus(q.Get("status"))
	switch status {
	case "", domain.AuditLogSuccess, domain.AuditLogFailure:
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "status must be success or failure")
		return
	}
	// level=warning,error,critical: any of these (comma separated).
	var levels []domain.AuditLogLevel
	for _, l := range strings.Split(q.Get("level"), ",") {
		switch lv := domain.AuditLogLevel(strings.TrimSpace(l)); lv {
		case "":
		case domain.AuditLogDebug, domain.AuditLogInfo, domain.AuditLogSuspicious, domain.AuditLogWarning,
			domain.AuditLogError, domain.AuditLogCritical:
			levels = append(levels, lv)
		default:
			writeError(w, http.StatusBadRequest, "invalid_request",
				"level must be a comma-separated list of debug, info, suspicious, warning, error, critical")
			return
		}
	}
	v, total, err := s.d.Admin.SearchAudit(r.Context(), realmFrom(r), repository.AuditSearch{
		UserID: q.Get("user"), ClientRef: q.Get("client"), Action: q.Get("action"), Status: status,
		Levels: levels, From: from, To: to, Page: p,
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.AuditView]{Items: items(v), Total: total, Offset: p.Offset, Limit: p.Limit})
}

// --- users ----------------------------------------------------------------------

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	p := page(r)
	q := r.URL.Query()
	status := domain.UserStatus(q.Get("status"))
	switch status {
	case "", domain.UserActive, domain.UserInactive, domain.UserSuspended:
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "status must be active, inactive or suspended")
		return
	}
	v, total, err := s.d.Admin.ListUsers(r.Context(), realmFrom(r), repository.UserSearch{
		Query: strings.TrimSpace(q.Get("q")), Status: status, GroupID: q.Get("group"), RoleID: q.Get("role"), Page: p,
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.UserSummary]{Items: items(v), Total: total, Offset: p.Offset, Limit: p.Limit})
}

func (s *Server) handleInviteUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username  string                 `json:"username"`
		Email     string                 `json:"email"`
		Profile   map[string]interface{} `json:"profile"`
		GroupIDs  []string               `json:"group_ids"`
		RoleIDs   []string               `json:"role_ids"`
		SendEmail bool                   `json:"send_email"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := s.d.Admin.InviteUser(r.Context(), adminFrom(r).actor, realmFrom(r), service.InviteUserInput{
		Username: in.Username, Email: in.Email, Profile: in.Profile, GroupIDs: in.GroupIDs, RoleIDs: in.RoleIDs, SendEmail: in.SendEmail,
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.GetUser(r.Context(), realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username *string                `json:"username"`
		Email    *string                `json:"email"`
		Status   *string                `json:"status"`
		Profile  map[string]interface{} `json:"profile"`
	}
	if !decode(w, r, &in) {
		return
	}
	upd := service.UpdateUserInput{Username: in.Username, Email: in.Email, Profile: in.Profile}
	if in.Status != nil {
		st := domain.UserStatus(*in.Status)
		upd.Status = &st
	}
	v, err := s.d.Admin.UpdateUser(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), upd)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.DeleteUser(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserGroups(w http.ResponseWriter, r *http.Request) {
	var in struct {
		GroupIDs []string `json:"group_ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.SetUserGroups(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.GroupIDs)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSetUserRoles(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RoleIDs []string `json:"role_ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.SetUserRoles(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.RoleIDs)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleResetUserMFA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := s.d.Admin.ResetUserMFA(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.Reason)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"methods_deleted": res.MethodsDeleted, "backup_codes_deleted": res.BackupCodesDeleted})
}

func (s *Server) handleUnlockUser(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.UnlockUser(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleActivationLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SendEmail bool `json:"send_email"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := s.d.Admin.ResendActivation(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.SendEmail)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.RevokeUserSessions(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- roles, groups, permissions -------------------------------------------------

type accessJSON struct {
	Name           *string   `json:"name"`
	Description    *string   `json:"description"`
	Active         *bool     `json:"active"`
	PermissionIDs  *[]string `json:"permission_ids"`
	ClientScopeIDs *[]string `json:"client_scope_ids"`
}

func (j accessJSON) input() service.AccessInput {
	return service.AccessInput{Name: j.Name, Description: j.Description, Active: j.Active,
		PermissionIDs: j.PermissionIDs, ClientScopeIDs: j.ClientScopeIDs}
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.ListRoles(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.AccessView]{Items: items(v), Total: len(v), Limit: len(v)})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var in accessJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.CreateRole(r.Context(), adminFrom(r).actor, realmFrom(r), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	var in accessJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.UpdateRole(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.DeleteRole(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.ListGroups(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.AccessView]{Items: items(v), Total: len(v), Limit: len(v)})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var in accessJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.CreateGroup(r.Context(), adminFrom(r).actor, realmFrom(r), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	var in accessJSON
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.UpdateGroup(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.input())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.DeleteGroup(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	p := page(r)
	v, total, err := s.d.Admin.GroupMembers(r.Context(), realmFrom(r), chi.URLParam(r, "id"), p)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.UserSummary]{Items: items(v), Total: total, Offset: p.Offset, Limit: p.Limit})
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.ListPermissions(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.PermissionView]{Items: items(v), Total: len(v), Limit: len(v)})
}

func (s *Server) handleCreatePermission(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resource    string `json:"resource"`
		Action      string `json:"action"`
		Description string `json:"description"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.d.Admin.CreatePermission(r.Context(), adminFrom(r).actor, realmFrom(r), service.CreatePermissionInput(in))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleDeletePermission(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Admin.DeletePermission(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id")); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
