package httpserver

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/adapters/accountui"
	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/i18n"
	"sso.internal/sso/internal/ratelimit"
)

// Address verification (audit B-13): the page the link of the "confirm your
// address" e-mail opens, and the account console's button that sends it.

const (
	routeVerifyEmail = "auth.verify_email"
	// The links are 256 random bits: the limit only keeps the endpoint
	// cheap, like the reset's.
	verifyPerIP = resetPerIP
)

// WithEmailVerification mounts the address verification page and the
// account console's "send a verification e-mail" (with WithAccountConsole).
func WithEmailVerification(v *service.EmailVerificationService) Option {
	return func(s *Server) { s.emailVerify = v }
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

// mountEmailVerification: the page, then the JSON call its script makes
// with the token of the URL fragment (never sent to the server by the
// browser on its own: it stays out of access logs, and a mail scanner that
// opens the link verifies nothing).
func (s *Server) mountEmailVerification(r chi.Router, pages *loginui.Pages) {
	r.Get("/auth/verify-email", func(w http.ResponseWriter, r *http.Request) {
		realm := realmFromContext(r)
		pages.RenderVerifyEmail(w, r, loginui.VerifyEmail{
			RealmDisplay: realmDisplay(realm.DisplayName, realm.Name),
			Base:         "/r/" + realm.Name,
			Assets:       "/r/" + realm.Name + "/auth/assets",
		})
	})
	r.With(requireJSON).Post("/auth/verify-email", s.handleVerifyEmail)
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	var req verifyEmailRequest
	if !decodeSmallJSON(w, r, &req) || req.Token == "" || len(req.Token) > 256 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ok, err := s.allowAll(r, limit{ratelimit.Key(routeVerifyEmail, realm.ID, "ip", clientIP(r)), verifyPerIP, resetWindow})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	_, err = s.emailVerify.Verify(r.Context(), realm.ID, req.Token, clientIP(r), r.UserAgent())
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
	case errors.Is(err, service.ErrEmailVerificationInvalid):
		writeError(w, http.StatusBadRequest, "invalid_or_expired_token")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

// selfRequester: the signed-in user asks, from the account console.
func selfRequester(r *http.Request, a *acct) service.VerificationRequester {
	return service.VerificationRequester{ActorType: domain.AuditActorUser, ActorID: a.user.ID, IPAddress: clientIP(r), UserAgent: r.UserAgent()}
}

// canVerifyEmail: the profile page offers "send a verification e-mail".
func (s *Server) canVerifyEmail(u *domain.User) bool {
	return s.emailVerify != nil && s.emailVerify.Enabled() && u.EmailVerifiedAt == nil && u.Email != ""
}

// handleAccountVerifyEmail: the profile page's "Send a verification
// e-mail".
func (s *Server) handleAccountVerifyEmail(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if s.emailVerify == nil {
		s.accountRedirect(w, r, accountBase(a.realm.Name))
		return
	}
	_, err := s.emailVerify.Send(r.Context(), a.user, selfRequester(r, a))
	switch {
	case err == nil:
		setFlash(w, a.realm.Name, "verify_sent", 0)
	case errors.Is(err, service.ErrEmailAlreadyVerified):
		// Verified in another tab meanwhile: the page shows it.
	case errors.Is(err, service.ErrEmailVerificationTooSoon):
		setFlash(w, a.realm.Name, "verify_too_soon", 0)
	case errors.Is(err, service.ErrEmailVerificationUnavailable):
		setFlash(w, a.realm.Name, "verify_unavailable", 0)
	default:
		s.accountFailure(w, r, err)
		return
	}
	s.accountRedirect(w, r, accountBase(a.realm.Name))
}

// --- e-mail change (where the realm allows it) ---------------------------------

var emailStepUpSubtitle = i18n.M("account.stepup.subtitle_email", "to change your e-mail address")

// emailCard: the anchor of the profile page's "Change your e-mail address".
const emailCard = "#email"

// canChangeEmail: the profile page offers "Change your e-mail address".
func (s *Server) canChangeEmail(r *http.Request, u *domain.User) bool {
	return s.emailVerify != nil && u.Status == domain.UserActive && s.emailVerify.EmailChangeAllowed(r.Context(), u.RealmID)
}

// emailStepUp: a change of address takes over where the password reset
// e-mails go, so it asks "Confirm it's you" like a security change. The
// confirmation happens on GET /profile/email.
func (s *Server) emailStepUp(w http.ResponseWriter, r *http.Request, a *acct) bool {
	return s.accountStepUpFor(w, r, a, accountBase(a.realm.Name)+"/profile/email", false, emailStepUpSubtitle, accountBase(a.realm.Name))
}

// handleAccountEmailGate: "Confirm it's you" for an e-mail change, then
// back to the profile page.
func (s *Server) handleAccountEmailGate(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if !s.emailStepUp(w, r, a) {
		return
	}
	s.accountRedirect(w, r, accountBase(a.realm.Name)+emailCard)
}

// handleAccountEmailChange: "Send the confirmation link". The address only
// changes once the link e-mailed to the new one is used.
func (s *Server) handleAccountEmailChange(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if s.emailVerify == nil {
		s.accountRedirect(w, r, accountBase(a.realm.Name))
		return
	}
	if !s.emailStepUp(w, r, a) {
		return
	}
	loc := s.loc(r)
	newEmail := r.PostForm.Get("new_email")
	fail := func(status int, msg string) {
		page := s.profilePage(w, r, a)
		page.NewEmail, page.EmailFormError = newEmail, msg
		s.accountPages.RenderPage(w, r, status, accountui.PageProfile, page)
	}
	ok, err := s.rateLimiter.Allow(r.Context(), ratelimit.Key(routeAccountEmail, a.realm.ID, "user", a.user.ID),
		accountEmailPerUser, loginRateLimitWindow)
	if err != nil {
		s.accountFailure(w, r, err)
		return
	}
	if !ok {
		fail(http.StatusTooManyRequests, loc.T("account.error.rate_limited", "Too many attempts. Wait a few minutes, then try again."))
		return
	}
	_, err = s.emailVerify.RequestEmailChange(r.Context(), a.user, newEmail, selfRequester(r, a))
	switch {
	case err == nil:
		setFlash(w, a.realm.Name, "email_change_sent", 0)
	case errors.Is(err, service.ErrInvalidEmail):
		fail(http.StatusUnprocessableEntity, loc.T("account.profile.email.invalid", "Enter an e-mail address, like name@example.com."))
		return
	case errors.Is(err, service.ErrEmailUnchanged):
		fail(http.StatusUnprocessableEntity, loc.T("account.profile.email.unchanged", "This already is your address."))
		return
	case errors.Is(err, service.ErrEmailTaken):
		fail(http.StatusUnprocessableEntity, loc.T("account.profile.email.taken", "Another account already uses this address. Choose another one."))
		return
	case errors.Is(err, service.ErrEmailChangeNotAllowed):
		setFlash(w, a.realm.Name, "email_change_disabled", 0) // the form is gone: a notice
	// In the form, next to the field: the card is low on the page, a notice
	// at its top would be out of sight.
	case errors.Is(err, service.ErrEmailVerificationTooSoon):
		fail(http.StatusTooManyRequests, loc.Text(flashText["verify_too_soon"]))
		return
	case errors.Is(err, service.ErrEmailVerificationUnavailable):
		fail(http.StatusServiceUnavailable, loc.Text(flashText["verify_unavailable"]))
		return
	default:
		s.accountFailure(w, r, err)
		return
	}
	s.accountRedirect(w, r, accountBase(a.realm.Name)+emailCard)
}

// handleAccountEmailChangeCancel: "Cancel the change". Keeping one's
// address needs no confirmation.
func (s *Server) handleAccountEmailChangeCancel(w http.ResponseWriter, r *http.Request) {
	a := acctFrom(r)
	if s.emailVerify == nil {
		s.accountRedirect(w, r, accountBase(a.realm.Name))
		return
	}
	if err := s.emailVerify.CancelEmailChange(r.Context(), a.user, selfRequester(r, a)); err != nil {
		s.accountFailure(w, r, err)
		return
	}
	setFlash(w, a.realm.Name, "email_change_cancelled", 0)
	s.accountRedirect(w, r, accountBase(a.realm.Name)+emailCard)
}
