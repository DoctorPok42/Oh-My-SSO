package httpserver

import (
	"log/slog"
	"net/http"

	"sso.internal/sso/internal/adapters/accountui"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/i18n"
)

// The "Language" card of the Profile page. A user chooses the language of
// their account: the console, the sign-in pages and the e-mails (profile
// "locale", also the OIDC "locale" claim, which the admin console follows).
//
// The choice is shared with the person's accounts in the other
// organizations signed in on this browser (the organization menu): realms
// are separate tenants and nothing links their accounts on the server, so
// the browser carries it. Saving sets the omsso_locale cookie (Path=/) and
// the next page asks account.js to POST /r/<other>/account/language/sync
// for each of those organizations; each one copies the cookie's language
// into its own account, with its own session. Without JavaScript, only
// this organization changes.

// languageOptions: the choices of the card, the page's language selected.
func (s *Server) languageOptions(r *http.Request) []accountui.LanguageOption {
	current := s.loc(r).Lang()
	langs := s.i18n.Languages()
	out := make([]accountui.LanguageOption, 0, len(langs))
	for _, l := range langs {
		out = append(out, accountui.LanguageOption{Tag: l.Tag, Name: l.Name, Selected: l.Tag == current})
	}
	return out
}

// handleAccountLanguage saves the language of the account.
func (s *Server) handleAccountLanguage(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	lang := s.i18n.Match(r.PostForm.Get("locale"))
	if lang == "" {
		setFlash(w, a.realm.Name, "bad_language", 0)
		s.accountRedirect(w, r, accountBase(a.realm.Name))
		return
	}
	if _, err := s.account.SetLocale(r.Context(), a.user, lang, s.accountEvent(r)); err != nil {
		s.accountFailure(w, r, err)
		return
	}
	i18n.SetCookie(w, lang, true)
	setFlash(w, a.realm.Name, "language_saved", 0)
	s.accountRedirect(w, r, accountBase(a.realm.Name))
}

// handleAccountLanguageSync gives this realm's account the language of the
// browser (the omsso_locale cookie), when this browser is signed in here.
// It takes no input: the cookie is set by this server, so a request from
// elsewhere (which the same-origin check refuses anyway) could only copy
// the person's own last choice. Always 204: account.js does not wait for it.
func (s *Server) handleAccountLanguageSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm := realmFromContext(r)
	defer w.WriteHeader(http.StatusNoContent)
	lang := s.i18n.Match(i18n.FromCookie(r))
	if lang == "" || s.mfa == nil {
		return
	}
	sess, err := s.sessions.Validate(ctx, realm.ID, sessionTokenFromRequest(r))
	if err != nil {
		return
	}
	u, err := s.mfa.User(ctx, sess.UserID)
	if err != nil || u.Status != domain.UserActive || u.RealmID != realm.ID || userLocale(u) == lang {
		return
	}
	if _, err := s.account.SetLocale(ctx, u, lang, s.accountEvent(r)); err != nil {
		slog.Default().WarnContext(ctx, "account console: language sync", "realm", realm.Name, "error", err)
	}
}
