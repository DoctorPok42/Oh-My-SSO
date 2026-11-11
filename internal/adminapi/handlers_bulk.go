package adminapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/i18n"
)

// Bulk actions: one action on up to the realm's bulk limit (Settings). What
// the whole selection needs is checked first (400, 404, 409 as any request);
// then the job is recorded and the answer is 202 with it, the items running
// in the background. GET /bulk-jobs/{id} follows it: items can be skipped (a
// guardrail said no) or fail one by one, and the finished job says which.

type bulkRequest struct {
	Action  string   `json:"action"`
	IDs     []string `json:"ids"`
	Reason  string   `json:"reason"`
	GroupID string   `json:"group_id"`
	RoleID  string   `json:"role_id"`
}

// bulk is the handler of a POST .../bulk.
func (s *Server) bulk(run func(context.Context, service.AdminActor, *domain.Realm, service.BulkInput, *i18n.Localizer) (*service.BulkJobView, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in bulkRequest
		if !decode(w, r, &in) {
			return
		}
		job, err := run(r.Context(), adminFrom(r).actor, realmFrom(r), service.BulkInput{
			Action: in.Action, IDs: in.IDs, Reason: in.Reason, GroupID: in.GroupID, RoleID: in.RoleID,
		}, localizer(r.Context()))
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	}
}

// handleGetBulkJob: GET /bulk-jobs/{id}, where a bulk action stands, or its
// report. Only the administrator who started it may read it.
func (s *Server) handleGetBulkJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.d.Admin.GetBulkJob(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), localizer(r.Context()))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleAddGroupMembers: a pasted list of usernames or e-mails.
func (s *Server) handleAddGroupMembers(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identifiers []string `json:"identifiers"`
	}
	if !decode(w, r, &in) {
		return
	}
	job, err := s.d.Admin.AddGroupMembers(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"), in.Identifiers, localizer(r.Context()))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// handleExportClients: GET /clients/export?ids=a,b, the configuration of the
// selected clients.
func (s *Server) handleExportClients(w http.ResponseWriter, r *http.Request) {
	v, err := s.d.Admin.ExportClients(r.Context(), realmFrom(r), strings.Split(r.URL.Query().Get("ids"), ","))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": v})
}

// handleBulkLimit: GET /bulk-limit, the most items one bulk action of this
// realm may touch (Settings). The console sizes its selections with it.
func (s *Server) handleBulkLimit(w http.ResponseWriter, r *http.Request) {
	n, err := s.d.Admin.BulkLimit(r.Context(), realmFrom(r).ID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"limit": n})
}
