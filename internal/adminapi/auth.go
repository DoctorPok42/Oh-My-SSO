package adminapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// Who may call the Admin API, checked on every request, in this order:
//
//  1. the caller's IP is in ADMIN_API_ALLOWED_CIDRS (when set): only the
//     admin console's server should ever reach this API;
//  2. "Authorization: Bearer <JWT>": signed by the master realm, issued to
//     "sso-admin", not expired (token.go);
//  3. the token's row: it exists, is an access token of "sso-admin" and was
//     not revoked;
//  4. the session behind it (claim "sid") is still active: revoking an
//     admin's session cuts the API at once. Each call counts as activity;
//  5. RBAC: the admin holds the permission of the route on "sso-admin";
//  6. for every change: a second factor verified less than
//     mfa_step_up_max_age_minutes ago (10 by default). Otherwise
//     403 {"error":"step_up_required"}: the console sends the admin through
//     the login page again (prompt=login), then retries.

type ctxKey int

const (
	ctxAdmin ctxKey = iota
	ctxRealm
)

// adminContext: what the auth chain learned about the caller.
type adminContext struct {
	actor   service.AdminActor
	user    *domain.User
	session *domain.Session
	master  *domain.Realm
	client  *domain.ClientApp // sso-admin
}

func adminFrom(r *http.Request) *adminContext {
	a, _ := r.Context().Value(ctxAdmin).(*adminContext)
	return a
}

func realmFrom(r *http.Request) *domain.Realm {
	realm, _ := r.Context().Value(ctxRealm).(*domain.Realm)
	return realm
}

// peerIP is the address of the TCP peer. X-Forwarded-For is NOT trusted: the
// only legitimate caller is the admin console's server, on a private network.
func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func (s *Server) allowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.AllowedNets) > 0 {
			ip := peerIP(r)
			allowed := false
			for _, n := range s.cfg.AllowedNets {
				if ip != nil && n.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				writeError(w, http.StatusForbidden, "ip_not_allowed", "this address may not call the Admin API")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate runs steps 2 to 4.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(raw) == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to the admin console")
			return
		}
		unauthorized := func() {
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "the session ended: sign in again")
		}

		master, err := s.d.Realms.GetByName(ctx, service.MasterRealmName)
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusServiceUnavailable, "not_bootstrapped", "run `idp-admin bootstrap` first")
			return
		}
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		client, err := s.d.Clients.GetByRealmAndClientID(ctx, master.ID, domain.InternalAdminClientID)
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusServiceUnavailable, "not_bootstrapped", "run `idp-admin bootstrap` first")
			return
		}
		if err != nil {
			writeServiceError(w, r, err)
			return
		}

		claims, err := s.verifier.verify(ctx, master.ID, strings.TrimSpace(raw))
		if errors.Is(err, errInvalidToken) {
			unauthorized()
			return
		}
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		tok, err := s.d.Tokens.GetByJTI(ctx, claims.JTI)
		if err != nil || tok.Type != domain.TokenAccessToken || tok.Revoked || tok.ClientRefID != client.ID ||
			!s.now().Before(tok.ExpiresAt) || tok.SessionID != claims.SessionID {
			unauthorized()
			return
		}
		sess, err := s.d.Sessions.TouchActive(ctx, claims.SessionID)
		if err != nil || sess.RealmID != master.ID {
			unauthorized()
			return
		}
		user, err := s.d.Users.GetByID(ctx, sess.UserID)
		if err != nil || user.Status != domain.UserActive || user.DeletedAt != nil {
			unauthorized()
			return
		}

		a := &adminContext{
			actor: service.AdminActor{UserID: user.ID, Username: user.Username, RealmID: master.ID,
				IPAddress: s.clientIP(r), UserAgent: s.clientUA(r)},
			user: user, session: sess, master: master, client: client,
		}
		ctx = context.WithValue(ctx, ctxAdmin, a)
		ctx = audit.WithActor(ctx, audit.Actor{UserID: user.ID, RealmID: master.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// clientIP / clientUA: the admin's own browser, as forwarded by the admin
// console (X-Admin-Client-IP / -User-Agent). Used for the audit log only,
// never for a security decision; the TCP peer otherwise.
func (s *Server) clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Admin-Client-IP")); v != "" && net.ParseIP(v) != nil {
		return v
	}
	if ip := peerIP(r); ip != nil {
		return ip.String()
	}
	return ""
}

func (s *Server) clientUA(r *http.Request) string {
	if v := r.Header.Get("X-Admin-Client-User-Agent"); v != "" {
		if len(v) > 512 {
			v = v[:512]
		}
		return v
	}
	return r.UserAgent()
}

// require checks one permission ("client", "write") on the sso-admin client.
func (s *Server) require(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := adminFrom(r)
			err := s.d.RBAC.Authorize(r.Context(), service.AuthorizeInput{
				RealmID: a.master.ID, UserID: a.user.ID, ClientRef: a.client.ID,
				Resource: resource, Action: action, IPAddress: a.actor.IPAddress, UserAgent: a.actor.UserAgent,
			})
			switch {
			case errors.Is(err, service.ErrForbidden):
				writeError(w, http.StatusForbidden, "forbidden", "you need the permission "+resource+":"+action)
			case err != nil:
				writeServiceError(w, r, err)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

// stepUpBody: what the console needs to send the admin through the login
// page again.
type stepUpBody struct {
	Error         string   `json:"error"`
	Message       string   `json:"message"`
	Methods       []string `json:"allowed_methods,omitempty"`
	MaxAgeSeconds int      `json:"max_age_seconds"`
}

// stepUp: every change needs a recent second factor (step 6).
func (s *Server) stepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := adminFrom(r)
		err := s.d.MFA.CheckStepUp(r.Context(), a.session, service.StepUpSensitiveAction)
		var su *service.StepUpRequiredError
		switch {
		case err == nil:
			next.ServeHTTP(w, r)
		case errors.As(err, &su):
			code, msg := "step_up_required", "confirm it's you: sign in again with your second factor"
			if su.Reason == service.StepUpNeedEnrollment {
				code, msg = "mfa_enrollment_required", "set up a second factor first"
			}
			methods := make([]string, 0, len(su.AllowedMethods))
			for _, m := range su.AllowedMethods {
				methods = append(methods, string(m))
			}
			writeJSON(w, http.StatusForbidden, stepUpBody{Error: code, Message: msg, Methods: methods,
				MaxAgeSeconds: int(su.MaxAge.Seconds())})
		default:
			writeServiceError(w, r, err)
		}
	})
}

// loadRealm resolves {realm} (any status: a disabled realm can still be
// administered, and re-enabled).
func (s *Server) loadRealm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm, err := s.d.Admin.RealmByName(r.Context(), chi.URLParam(r, "realm"))
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRealm, realm)))
	})
}
