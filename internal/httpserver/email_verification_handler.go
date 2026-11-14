package httpserver

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
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
	_, err := s.emailVerify.Send(r.Context(), a.user, service.VerificationRequester{
		ActorType: domain.AuditActorUser, ActorID: a.user.ID, IPAddress: clientIP(r), UserAgent: r.UserAgent(),
	})
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
