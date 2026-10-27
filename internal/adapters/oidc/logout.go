package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// RP-initiated logout (OIDC RP-Initiated Logout 1.0). The id_token_hint
// names the session to end (its "sid"):
//
//	that session is over               nothing to do, back to the application
//	it is the session of this browser  signed out at once
//	anything else                      "Sign out of <realm>?" first: section 2
//	                                   of the spec says the OP MUST ask when
//	                                   the hint does not belong to the current
//	                                   session (no cookie, another account...)

// logoutTTL: time to answer the confirmation page.
const logoutTTL = 10 * time.Minute

func pendingLogoutKey(id string) string { return "oidc:lo:{" + id + "}" }

// pendingLogout waits for the answer of the confirmation page.
type pendingLogout struct {
	ID          string    `json:"id"`
	RealmID     string    `json:"rid"`
	SessionID   string    `json:"sid"`
	ClientID    string    `json:"cid,omitempty"`
	RedirectURL string    `json:"ruri"` // where the browser goes after the answer
	BrowserHash string    `json:"bh"`
	TokenHash   string    `json:"th,omitempty"` // one-time token of the page on screen
	CreatedAt   time.Time `json:"cat"`
}

// logoutInfo is what TerminateSessionFromRequest needs from the browser's
// request (the library only passes it the context).
type logoutInfo struct {
	sessionToken string
	ip           string
	userAgent    string
}

type logoutInfoKey struct{}

func (a *Adapter) logoutContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := logoutInfo{ip: remoteIP(r), userAgent: r.UserAgent()}
		if c, err := r.Cookie(a.cfg.SessionCookieName); err == nil {
			info.sessionToken = c.Value
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), logoutInfoKey{}, info)))
	})
}

func logoutInfoFrom(ctx context.Context) logoutInfo {
	info, _ := ctx.Value(logoutInfoKey{}).(logoutInfo)
	return info
}

// endSession decides for a validated logout request (see the table above)
// and returns where the browser goes next.
func (a *Adapter) endSession(ctx context.Context, realm Realm, sid, clientID, redirect string) (string, error) {
	sess, err := a.core.GetSession(ctx, sid)
	if err != nil || sess.RealmID != realm.ID {
		return redirect, nil // already over (or not ours): nothing to sign out
	}
	info := logoutInfoFrom(ctx)
	if info.sessionToken != "" {
		if mine, err := a.core.ValidateSession(ctx, realm.ID, info.sessionToken); err == nil && mine.ID == sid {
			if err := a.core.Logout(ctx, core.LogoutRequest{
				SessionID: sid, Via: domain.LogoutViaOIDC, ClientID: clientID,
				IPAddress: info.ip, UserAgent: info.userAgent,
			}); err != nil {
				return "", err
			}
			return redirect, nil
		}
	}

	bh, ok := browserHashFrom(ctx)
	if !ok {
		return "", errors.New("oidc: logout without a browser binding")
	}
	p := pendingLogout{
		ID: rand.Text(), RealmID: realm.ID, SessionID: sid, ClientID: clientID,
		RedirectURL: redirect, BrowserHash: bh, CreatedAt: a.now(),
	}
	if err := a.savePendingLogout(ctx, &p); err != nil {
		return "", err
	}
	return a.issuer(realm.Name) + "/oidc/logout/confirm?id=" + url.QueryEscape(p.ID), nil
}

// handleLogoutConfirmPage shows "Sign out of <realm>?".
func (a *Adapter) handleLogoutConfirmPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	p, err := a.loadPendingLogout(ctx, realm, r.URL.Query().Get("id"))
	if err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgLogoutExpired)
		return
	}
	if !browserHashMatches(r, p.BrowserHash) {
		a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
		return
	}
	acc, err := a.core.SessionAccount(ctx, p.SessionID)
	if err != nil {
		// Ended meanwhile: nothing left to ask.
		_ = a.store.Delete(ctx, pendingLogoutKey(p.ID))
		http.Redirect(w, r, p.RedirectURL, http.StatusFound)
		return
	}
	clientName := p.ClientID
	if pc, err := a.core.LookupClient(ctx, realm.ID, protocolOIDC, p.ClientID); err == nil {
		clientName = firstNonEmpty(pc.App.Name, pc.App.ClientID)
	}

	// A new token at each display: only the form on screen can answer.
	token := rand.Text()
	p.TokenHash = sha256Hex(token)
	if err := a.savePendingLogout(ctx, p); err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgLogoutExpired)
		return
	}
	base := "/r/" + realm.Name
	a.pages.RenderLogoutConfirm(w, loginui.LogoutConfirm{
		RealmDisplay: firstNonEmpty(realm.DisplayName, realm.Name),
		ClientName:   firstNonEmpty(clientName, "An application"),
		Account:      acc.Identifier,
		Action:       base + "/oidc/logout/confirm",
		RequestID:    p.ID,
		Token:        token,
		Assets:       base + "/oidc/assets",
	})
}

// handleLogoutConfirm receives the answer. "Sign out" ends the session;
// anything else (Cancel) keeps it. Either way the browser goes back to the
// application, which already signed the user out on its side.
func (a *Adapter) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgLogoutExpired)
		return
	}
	id := r.PostForm.Get("id")
	p, err := a.loadPendingLogout(ctx, realm, id)
	if err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgLogoutExpired)
		return
	}
	if !browserHashMatches(r, p.BrowserHash) {
		a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
		return
	}
	token := r.PostForm.Get("logout_token")
	if p.TokenHash == "" || token == "" ||
		subtle.ConstantTimeCompare([]byte(sha256Hex(token)), []byte(p.TokenHash)) != 1 {
		// A stale or forged form: show the page again (fresh token).
		http.Redirect(w, r, a.issuer(realm.Name)+"/oidc/logout/confirm?id="+url.QueryEscape(p.ID), http.StatusSeeOther)
		return
	}
	// Single use: a second submit (or tab) finds nothing.
	if data, err := a.store.Take(ctx, pendingLogoutKey(p.ID)); err != nil || data == nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgLogoutExpired)
		return
	}
	if r.PostForm.Get("decision") == "signout" {
		if err := a.core.Logout(ctx, core.LogoutRequest{
			SessionID: p.SessionID, Via: domain.LogoutViaOIDC, ClientID: p.ClientID,
			IPAddress: remoteIP(r), UserAgent: r.UserAgent(), Confirmed: true,
		}); err != nil {
			a.logger.ErrorContext(ctx, "oidc: logout", "error", err)
			a.renderMessage(w, r, http.StatusInternalServerError, msgLogoutFailed)
			return
		}
	}
	http.Redirect(w, r, p.RedirectURL, http.StatusSeeOther)
}

func (a *Adapter) savePendingLogout(ctx context.Context, p *pendingLogout) error {
	left := logoutTTL - a.now().Sub(p.CreatedAt)
	if left <= 0 {
		return errAuthRequestNotFound
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return a.store.Put(ctx, pendingLogoutKey(p.ID), data, left)
}

func (a *Adapter) loadPendingLogout(ctx context.Context, realm Realm, id string) (*pendingLogout, error) {
	if id == "" {
		return nil, errAuthRequestNotFound
	}
	data, err := a.store.Get(ctx, pendingLogoutKey(id))
	if err != nil {
		return nil, fmt.Errorf("load pending logout: %w", err)
	}
	if data == nil {
		return nil, errAuthRequestNotFound
	}
	var p pendingLogout
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode pending logout: %w", err)
	}
	if p.ID != id || p.RealmID != realm.ID {
		return nil, errAuthRequestNotFound
	}
	return &p, nil
}
