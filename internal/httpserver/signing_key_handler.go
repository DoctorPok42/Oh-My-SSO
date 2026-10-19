package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

// RBAC permission (resource, action) protecting the key admin endpoints.
// A user needs a Role/Group granting it on the realm's "sso-admin" client.
const (
	permResourceSigningKey = "signing_key"
	permActionRead         = "read"
	permActionRotate       = "rotate"

	maxAdminBodyBytes = 4 << 10 // 4 KiB is plenty for these small JSON bodies
)

// KeyRotator is the part of service.KeyRotationService the admin endpoints
// need (same code path as the "idp keys" CLI).
type KeyRotator interface {
	Rotate(ctx context.Context, in service.RotateInput) (*service.RotateResult, error)
	// Activate is the second step of a SAML key rotation (Step 11).
	Activate(ctx context.Context, in service.ActivateInput) (*service.RotateResult, error)
	RetireExpired(ctx context.Context, realmID, triggeredBy string) ([]*domain.SigningKey, error)
	List(ctx context.Context, realmID string) ([]*domain.SigningKey, error)
}

type rotateRequest struct {
	// Purpose: "jwt_signing" (default) or "saml_signing" (Step 11: the new
	// SAML key is "pending" until POST /activate).
	Purpose     string `json:"purpose,omitempty"`
	KeyType     string `json:"key_type,omitempty"`    // "RSA", "EC" or empty (same as current)
	GraceHours  int    `json:"grace_hours,omitempty"` // 0 = realm setting
	Compromised bool   `json:"compromised,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// signingKeyView is what we show about a key. Deliberately NOT included:
// kms_key_reference (internal pointer into the KMS, useless to a client).
type signingKeyView struct {
	Kid         string     `json:"kid"`
	KeyType     string     `json:"key_type"`
	Purpose     string     `json:"purpose"`
	Status      string     `json:"status"`
	KMSBackend  string     `json:"kms_backend"`
	CreatedAt   time.Time  `json:"created_at"`
	RetireAfter *time.Time `json:"retire_after,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

// activateRequest: POST /admin/signing-keys/activate (Step 11).
type activateRequest struct {
	Purpose    string `json:"purpose,omitempty"`     // default "saml_signing"
	GraceHours int    `json:"grace_hours,omitempty"` // 0 = realm setting
	Reason     string `json:"reason,omitempty"`
}

type rotateResponse struct {
	NewKey     signingKeyView   `json:"new_key"`
	Rotating   []signingKeyView `json:"rotating"`
	Retired    []signingKeyView `json:"retired"`
	GraceHours float64          `json:"grace_hours"`
	Warning    string           `json:"warning,omitempty"`
}

type keysResponse struct {
	Keys []signingKeyView `json:"keys"`
}

func (s *Server) mountSigningKeyAdmin(r chi.Router) {
	r.Route("/admin/signing-keys", func(r chi.Router) {
		r.Use(s.requireSession)
		r.With(s.requirePermission(permResourceSigningKey, permActionRead)).
			Get("/", s.handleListSigningKeys)
		// Rotating keys is a sensitive action: a recent second factor (or a
		// recent login for users without any) is needed on top of the
		// permission (Step 9). No-op when the server runs without MFA.
		stepUp := s.requireStepUp(service.StepUpSensitiveAction)
		r.With(s.requirePermission(permResourceSigningKey, permActionRotate), stepUp, requireJSON).
			Post("/rotate", s.handleRotateSigningKey)
		r.With(s.requirePermission(permResourceSigningKey, permActionRotate), stepUp, requireJSON).
			Post("/activate", s.handleActivateSigningKey)
		r.With(s.requirePermission(permResourceSigningKey, permActionRotate), stepUp, requireJSON).
			Post("/retire-expired", s.handleRetireExpiredSigningKeys)
	})
}

func (s *Server) handleListSigningKeys(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	keys, err := s.keyRotator.List(r.Context(), realm.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, keysResponse{Keys: toKeyViews(keys)})
}

func (s *Server) handleRotateSigningKey(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	sess := sessionFromContext(r)

	var req rotateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBodyBytes))
	dec.DisallowUnknownFields() // a typo like "compromized" must not be ignored
	// io.EOF = empty body: allowed, it means "all defaults".
	if err := dec.Decode(&req); (err != nil && !errors.Is(err, io.EOF)) || req.GraceHours < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	switch domain.SigningKeyType(req.KeyType) {
	case "", domain.SigningKeyRSA, domain.SigningKeyEC:
	default:
		writeError(w, http.StatusBadRequest, "unsupported_key_type")
		return
	}
	purpose, ok := rotationPurpose(req.Purpose)
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported_purpose")
		return
	}

	res, err := s.keyRotator.Rotate(r.Context(), service.RotateInput{
		RealmID:     realm.ID,
		Purpose:     purpose,
		KeyType:     domain.SigningKeyType(req.KeyType),
		Grace:       time.Duration(req.GraceHours) * time.Hour,
		Compromised: req.Compromised,
		TriggeredBy: "user:" + sess.UserID,
		Reason:      req.Reason,
	})
	if res == nil || res.NewKey == nil {
		switch {
		case errors.Is(err, service.ErrGraceTooShort):
			writeError(w, http.StatusBadRequest, "grace_too_short")
		case errors.Is(err, service.ErrCompromisedReasonRequired):
			writeError(w, http.StatusBadRequest, "reason_required")
		case errors.Is(err, service.ErrUnsupportedRotationPurpose):
			writeError(w, http.StatusBadRequest, "unsupported_purpose")
		case errors.Is(err, service.ErrSAMLKeyMustBeRSA):
			writeError(w, http.StatusBadRequest, "unsupported_key_type")
		case errors.Is(err, service.ErrPendingKeyExists):
			writeError(w, http.StatusConflict, "pending_key_exists")
		default:
			slog.ErrorContext(r.Context(), "signing key rotation failed", "realm_id", realm.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	resp := rotateResponse{
		NewKey:     toKeyView(res.NewKey),
		Rotating:   toKeyViews(res.Rotating),
		Retired:    toKeyViews(res.Retired),
		GraceHours: res.Grace.Hours(),
	}
	if err != nil {
		// The new key exists and signs; some follow-up step failed (e.g. a
		// log write). Report success with a warning rather than a 500 that
		// would invite a second, unnecessary rotation.
		slog.ErrorContext(r.Context(), "signing key rotation partially failed", "realm_id", realm.ID, "error", err)
		resp.Warning = "new key is active, but some follow-up steps failed: check the server logs and run retire-expired or rotate again later"
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleActivateSigningKey: second step of a SAML key rotation (Step 11).
// The pending key starts to sign, the previous one enters its grace period.
func (s *Server) handleActivateSigningKey(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	sess := sessionFromContext(r)

	var req activateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); (err != nil && !errors.Is(err, io.EOF)) || req.GraceHours < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	purpose := domain.SigningKeyPurposeSAMLSigning
	if req.Purpose != "" {
		purpose = domain.SigningKeyPurpose(req.Purpose)
	}
	res, err := s.keyRotator.Activate(r.Context(), service.ActivateInput{
		RealmID:     realm.ID,
		Purpose:     purpose,
		Grace:       time.Duration(req.GraceHours) * time.Hour,
		TriggeredBy: "user:" + sess.UserID,
		Reason:      req.Reason,
	})
	if res == nil || res.NewKey == nil {
		switch {
		case errors.Is(err, service.ErrNoPendingKey):
			writeError(w, http.StatusConflict, "no_pending_key")
		case errors.Is(err, service.ErrActivationNotSupported):
			writeError(w, http.StatusBadRequest, "unsupported_purpose")
		case errors.Is(err, service.ErrGraceTooShort):
			writeError(w, http.StatusBadRequest, "grace_too_short")
		default:
			slog.ErrorContext(r.Context(), "signing key activation failed", "realm_id", realm.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		return
	}
	resp := rotateResponse{
		NewKey:     toKeyView(res.NewKey),
		Rotating:   toKeyViews(res.Rotating),
		Retired:    toKeyViews(res.Retired),
		GraceHours: res.Grace.Hours(),
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "signing key activation partially failed", "realm_id", realm.ID, "error", err)
		resp.Warning = "the key signs now, but some follow-up steps failed: check the server logs"
	}
	writeJSON(w, http.StatusOK, resp)
}

// rotationPurpose maps the "purpose" of a rotate request (empty: JWT).
func rotationPurpose(v string) (domain.SigningKeyPurpose, bool) {
	switch domain.SigningKeyPurpose(v) {
	case "", domain.SigningKeyPurposeJWT:
		return domain.SigningKeyPurposeJWT, true
	case domain.SigningKeyPurposeSAMLSigning:
		return domain.SigningKeyPurposeSAMLSigning, true
	default:
		return "", false
	}
}

func (s *Server) handleRetireExpiredSigningKeys(w http.ResponseWriter, r *http.Request) {
	realm := realmFromContext(r)
	sess := sessionFromContext(r)

	retired, err := s.keyRotator.RetireExpired(r.Context(), realm.ID, "user:"+sess.UserID)
	if err != nil {
		slog.ErrorContext(r.Context(), "retire expired signing keys failed", "realm_id", realm.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, keysResponse{Keys: toKeyViews(retired)})
}

// requireJSON refuses state-changing requests that are not JSON. Together
// with the SameSite=Lax session cookie, it stops a malicious web page from
// submitting a plain HTML form to these endpoints (CSRF): a browser cannot
// send "Content-Type: application/json" cross-site without a CORS preflight,
// which we never approve.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "json_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func toKeyView(k *domain.SigningKey) signingKeyView {
	v := signingKeyView{
		Kid:        k.Kid,
		KeyType:    string(k.KeyType),
		Purpose:    string(k.Purpose),
		Status:     string(k.Status),
		KMSBackend: k.KMSBackend,
		CreatedAt:  k.CreatedAt,
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

func toKeyViews(keys []*domain.SigningKey) []signingKeyView {
	out := make([]signingKeyView, 0, len(keys)) // [] not null in JSON
	for _, k := range keys {
		out = append(out, toKeyView(k))
	}
	return out
}
