package adminapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/service"
)

// maxImportBodyBytes: the file travels inside JSON, where a quote or a line
// break takes two bytes. The service then measures the file itself.
const maxImportBodyBytes = 2*service.MaxUserImportBytes + 4<<10

func (s *Server) handlePreviewUserImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CSV string `json:"csv"`
	}
	if !decodeUpTo(w, r, &in, maxImportBodyBytes) {
		return
	}
	res, err := s.d.Admin.PreviewUserImport(r.Context(), realmFrom(r), in.CSV, localizer(r.Context()))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleStartUserImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CSV            string `json:"csv"`
		FileName       string `json:"file_name"`
		SendEmail      bool   `json:"send_email"`
		NotifyWhenDone bool   `json:"notify_when_done"`
	}
	if !decodeUpTo(w, r, &in, maxImportBodyBytes) {
		return
	}
	job, err := s.d.Admin.StartUserImport(r.Context(), adminFrom(r).actor, realmFrom(r), service.StartUserImportInput{
		CSV: in.CSV, FileName: in.FileName, SendEmail: in.SendEmail, NotifyWhenDone: in.NotifyWhenDone,
		Localizer: localizer(r.Context()),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleListUserImports(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.d.Admin.ListUserImports(r.Context(), realmFrom(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items(jobs)})
}

func (s *Server) handleGetUserImport(w http.ResponseWriter, r *http.Request) {
	job, err := s.d.Admin.GetUserImport(r.Context(), realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleResendImportInvitations e-mails a new activation link to the
// accounts of an import whose invitation did not get through.
func (s *Server) handleResendImportInvitations(w http.ResponseWriter, r *http.Request) {
	sent, err := s.d.Admin.ResendFailedImportInvitations(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"sent": sent})
}

func (s *Server) handleUserImportLinks(w http.ResponseWriter, r *http.Request) {
	links, err := s.d.Admin.UserImportActivationLinks(r.Context(), adminFrom(r).actor, realmFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, links)
}
