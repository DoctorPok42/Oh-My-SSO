package httpserver

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/service"
)


const maxWebAuthnBodySize = 64 << 10

type passkeyRegisterRequest struct {
	Kind string `json:"kind"` // "passkey" (default) or "security_key"
	Name string `json:"name"`
}

func (s *Server) mountWebAuthn(r chi.Router) {
	r.Route("/auth/mfa/webauthn", func(r chi.Router) {
		r.Use(requireJSON)
		r.Post("/options", s.handlePasskeyLoginOptions)
		r.Post("/verify", s.handlePasskeyLoginVerify)
	})
	r.Route("/auth/step-up/webauthn", func(r chi.Router) {
		r.Use(s.requireSession, requireJSON)
		r.Post("/options", s.handlePasskeyStepUpOptions)
		r.Post("/verify", s.handlePasskeyStepUpVerify)
	})
	r.Route("/account/mfa/webauthn/register", func(r chi.Router) {
		r.Use(s.requireSession, requireJSON)
		r.With(s.requireStepUp(service.StepUpAccountSecurity)).Post("/options", s.handlePasskeyRegisterOptions)
		r.Post("/verify", s.handlePasskeyRegisterVerify)
	})
}

func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	options, err := s.mfa.BeginPasskeyLogin(r.Context(), realm.ID, mfaChallengeTokenFromRequest(r))
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeRawJSON(w, options)
}

func (s *Server) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if !s.allowMFAFromIP(w, r, realm.ID) {
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	res, err := s.mfa.FinishPasskeyLogin(r.Context(), service.VerifyPasskeyLoginInput{
		RealmID:        realm.ID,
		ChallengeToken: mfaChallengeTokenFromRequest(r),
		Response:       body,
		IPAddress:      clientIP(r),
		UserAgent:      r.UserAgent(),
	})
	if err != nil {
		if err == service.ErrMFAChallengeInvalid {
			clearMFAChallengeCookie(w, realm.Name)
		}
		s.writeMFAError(w, err)
		return
	}
	s.writeVerifiedLogin(w, realm.Name, res)
}

func (s *Server) handlePasskeyStepUpOptions(w http.ResponseWriter, r *http.Request) {
	options, err := s.mfa.BeginPasskeyStepUp(r.Context(), sessionFromContext(r))
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeRawJSON(w, options)
}

func (s *Server) handlePasskeyStepUpVerify(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	if !s.allowMFAFromIP(w, r, realm.ID) {
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	upd, method, err := s.mfa.FinishPasskeyStepUp(r.Context(), sessionFromContext(r), body, clientIP(r), r.UserAgent())
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stepUpVerifyResponse{MFAMethod: string(method), MFAVerifiedAt: upd.MFAVerifiedAt})
}

func (s *Server) handlePasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	var req passkeyRegisterRequest
	if !decodeSmallJSON(w, r, &req) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	kind := service.PasskeyKind(req.Kind)
	if kind == "" {
		kind = service.PasskeyKindPasskey
	}
	options, err := s.mfa.BeginPasskeyRegistration(r.Context(), user, sessionFromContext(r), kind, req.Name)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	writeRawJSON(w, options)
}

func (s *Server) handlePasskeyRegisterVerify(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(w, r)
	if !ok {
		return
	}
	body, ok := readWebAuthnBody(w, r)
	if !ok {
		return
	}
	res, err := s.mfa.FinishPasskeyRegistration(r.Context(), user, sessionFromContext(r), body)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, enrollmentResponse{Method: toMFAMethodView(res.Method), BackupCodes: res.BackupCodes})
}

func readWebAuthnBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize))
	if err != nil || !json.Valid(body) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

// writeRawJSON sends JSON already encoded by the WebAuthn library.
func writeRawJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
