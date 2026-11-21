package httpserver

import (
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"sso.internal/sso/internal/adapters/accountui"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httptimeout"
	"sso.internal/sso/internal/i18n"
)

// "Your data" (GDPR articles 15, 17 and 20): the user asks for a copy of
// their data, made in the background (service.RequestDataExport), and
// downloads it once ready; where the organization allows it, they ask for
// their account to be deleted, or keep it after all. Every step needs a
// recent "Confirm it's you": a stolen session must not walk away with
// everything, nor delete the account.

var dataStepUpSubtitle = i18n.M("account.stepup.subtitle_data", "to get a copy of your data")

// dataDownloadBudget: the time to send a copy of the data, at worst a few
// megabytes over a slow connection.
const dataDownloadBudget = 5 * time.Minute

func (s *Server) dataStepUp(w http.ResponseWriter, r *http.Request, a *acct) bool {
	page := accountBase(a.realm.Name) + "/data"
	return s.accountStepUpFor(w, r, a, page, false, dataStepUpSubtitle, accountBase(a.realm.Name))
}

func (s *Server) handleAccountData(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.dataStepUp(w, r, a) {
		return
	}
	e, err := s.account.DataExport(r.Context(), a.user)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	page := s.dataPage(w, r, a)
	if e != nil {
		page.Status, page.MadeAt, page.ExpiresAt = string(e.Status), e.CreatedAt, e.ExpiresAt
	}
	s.accountPages.RenderPage(w, r, http.StatusOK, accountui.PageData, page)
}

func (s *Server) dataPage(w http.ResponseWriter, r *http.Request, a *acct) accountui.DataPage {
	return accountui.DataPage{
		Layout:          s.accountLayout(w, r, a, accountui.PageData, i18n.M("account.tab.data", "Your data")),
		KeepDays:        int(service.DataExportTTL.Hours() / 24),
		DeletionAllowed: s.account.AccountDeletionAllowed(r.Context(), a.realm),
		DeletionDays:    int(service.AccountDeletionDelay.Hours() / 24),
	}
}

// handleAccountDeletion: "Delete my account" (GDPR article 17), where the
// organization allows it. The account is signed out everywhere at once: the
// answer is a page saying when it will be deleted and how to keep it.
func (s *Server) handleAccountDeletion(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.dataStepUp(w, r, a) {
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		page := s.dataPage(w, r, a)
		page.FormError = s.loc(r).T("account.deletion.confirm_missing", "Tick the box to confirm.")
		s.accountPages.RenderPage(w, r, http.StatusUnprocessableEntity, accountui.PageData, page)
		return
	}
	at, err := s.account.RequestDeletion(r.Context(), a.realm, a.user, s.accountEvent(r))
	switch {
	case errors.Is(err, service.ErrAccountDeletionDisabled):
		setFlash(w, a.realm.Name, "deletion_disabled", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/data")
		return
	case err != nil:
		s.accountFailure(w, r, err)
		return
	}
	s.accountMessage(w, r, http.StatusOK, i18n.M("account.deletion.done.title", "Your account will be deleted"),
		i18n.M("account.deletion.done.text", "It will be deleted for good on {date}, and you are signed out everywhere. Changed your mind? Sign in to your account before then and choose \"Keep my account\".",
			"date", s.loc(r).DateTime(at)), "")
}

func (s *Server) handleAccountDeletionCancel(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.dataStepUp(w, r, a) {
		return
	}
	flash := "deletion_cancelled"
	if err := s.account.CancelDeletion(r.Context(), a.user, s.accountEvent(r)); errors.Is(err, service.ErrAccountDeletionNotScheduled) {
		flash = "not_found"
	} else if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	setFlash(w, a.realm.Name, flash, 0)
	s.accountRedirect(w, r, accountBase(a.realm.Name)+"/data")
}

func (s *Server) handleAccountDataExport(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.dataStepUp(w, r, a) {
		return
	}
	_, err := s.account.RequestDataExport(r.Context(), a.realm, a.user, s.accountEvent(r))
	flash := "export_requested"
	switch {
	case errors.Is(err, service.ErrDataExportRunning):
		flash = "export_running"
	case errors.Is(err, service.ErrDataExportStopping):
		flash = "export_stopping"
	case err != nil:
		s.accountFailure(w, r, err)
		return
	}
	setFlash(w, a.realm.Name, flash, 0)
	s.accountRedirect(w, r, accountBase(a.realm.Name)+"/data")
}

func (s *Server) handleAccountDataDownload(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	// Not shown in place like the page: the answer is a file, so a
	// confirmation is asked for on the page, and the download starts from
	// there.
	if err := s.mfa.CheckStepUp(r.Context(), a.sess, service.StepUpAccountSecurity); err != nil {
		setFlash(w, a.realm.Name, "confirm_first", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/data")
		return
	}
	e, err := s.account.DownloadDataExport(r.Context(), a.user, s.accountEvent(r))
	if errors.Is(err, service.ErrDataExportNotReady) {
		setFlash(w, a.realm.Name, "export_gone", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name)+"/data")
		return
	}
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	// Several megabytes to a phone take longer than the public write
	// timeout; the caller confirmed it's them above.
	httptimeout.Extend(w, r, dataDownloadBudget)
	accountui.SecurityHeaders(w.Header())
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": a.realm.Name + "-data-" + e.CreatedAt.UTC().Format("2006-01-02") + ".json",
	}))
	h.Set("Content-Length", strconv.Itoa(len(e.Data)))
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(e.Data)
}
