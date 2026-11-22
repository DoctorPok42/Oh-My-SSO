package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Account console (Step 14c, spec-panel-user.md): what a signed-in user may
// see and change about their own account. Every method acts on the user it
// is given, never on another one: the HTTP layer passes the user of the
// session, and every id coming from a form (a session, an application, a
// trusted device) is checked to belong to that user before anything happens.
//
// Second factors are managed by MFAService (enrol, remove, backup codes):
// it already checks, audits and notifies. Every change made here writes an
// AuditLog entry with the user as actor (spec: "toute action est journalisée").

var (
	ErrWrongPassword     = errors.New("service: the current password is wrong")
	ErrPasswordUnchanged = errors.New("service: the new password is the current one")
	ErrNoPassword        = errors.New("service: the account has no password yet")
	ErrInvalidName       = errors.New("service: invalid name")
	ErrCurrentSession    = errors.New("service: this is the session in use")
	ErrSessionNotFound   = errors.New("service: no such session for this user")
	ErrAppNotFound       = errors.New("service: no such application for this user")
)

const (
	// maxNameLength: of a first or last name, in characters.
	maxNameLength = 100
	// maxAccountSessions: more live sessions than that are not listed (the
	// realm's idle timeout keeps the list short).
	maxAccountSessions = 100
)

// AccountDeps: what the account console reads and changes.
type AccountDeps struct {
	Users         repository.UserRepository
	Admin         repository.AdminRepository // sessions search, profile, audit search
	Settings      repository.InstanceSettingsRepository
	Clients       repository.ClientRepository
	ClientScopes  repository.ClientScopeRepository
	Tokens        repository.TokenRepository
	LoginAttempts repository.LoginAttemptRepository
	Audit         repository.AuditLogRepository
	MFAMethods    repository.MfaMethodRepository  // optional: second factors in the copy of the data
	DataExports   repository.DataExportRepository // optional: without it, no copy of the data

	Sessions       *SessionService
	Consents       *ConsentService
	TrustedDevices *TrustedDeviceService
	Policy         *PasswordPolicyService
	Erasure        *ErasureService // optional: without it, no account deletion

	Notifier Notifier      // optional: "password changed" e-mail
	GeoIP    GeoIPResolver // optional: country of an IP address
	Now      func() time.Time
	Logger   *slog.Logger
}

type AccountService struct {
	d        AccountDeps
	settings *settingsCache
	exports  *jobRunner // copies of the data being made (account_export.go)
}

func NewAccountService(d AccountDeps) *AccountService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Notifier == nil {
		d.Notifier = NopNotifier{}
	}
	return &AccountService{d: d, settings: newSettingsCache(d.Settings, d.Logger), exports: newJobRunner()}
}

// AccountEvent: where a change comes from, for the audit log and e-mails.
type AccountEvent struct {
	IPAddress string
	UserAgent string
}

// Country returns the English name of the country of an IP address, or ""
// (no GeoIP database, private address...).
func (s *AccountService) Country(ip string) string {
	if s.d.GeoIP == nil || ip == "" {
		return ""
	}
	if _, name, ok := s.d.GeoIP.Country(ip); ok {
		return name
	}
	return ""
}

// --- profile ---------------------------------------------------------------

// NameInput: the names a user may change themselves (decision of Step 14c:
// first and last name only; the e-mail address and the username stay with
// the administrators).
type NameInput struct {
	GivenName  string
	FamilyName string
}

// UpdateName sets profile.given_name and profile.family_name, and
// profile.name to both joined (the display name of the OIDC "name" claim).
// An empty value removes the key. It returns the user with the new profile.
func (s *AccountService) UpdateName(ctx context.Context, user *domain.User, in NameInput, ev AccountEvent) (*domain.User, error) {
	given, err := cleanName(in.GivenName)
	if err != nil {
		return nil, err
	}
	family, err := cleanName(in.FamilyName)
	if err != nil {
		return nil, err
	}
	profile := maps.Clone(user.Profile)
	if profile == nil {
		profile = map[string]interface{}{}
	}
	set := func(key, value string) {
		if value == "" {
			delete(profile, key)
		} else {
			profile[key] = value
		}
	}
	set("given_name", given)
	set("family_name", family)
	set("name", strings.TrimSpace(given+" "+family))

	var changed []string
	for _, k := range []string{"given_name", "family_name", "name"} {
		if fmt.Sprint(profile[k]) != fmt.Sprint(user.Profile[k]) {
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 {
		return user, nil
	}
	if err := s.d.Admin.SetUserProfile(ctx, user.ID, profile); err != nil {
		return nil, fmt.Errorf("update name: %w", err)
	}
	s.audit(ctx, user, audit.UserProfileUpdated, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"fields": changed})
	out := *user
	out.Profile = profile
	return &out, nil
}

// SetLocale sets profile.locale, the language the user chose (the pages,
// the e-mails, and the OIDC "locale" claim). The caller checks that the
// server has it (package i18n). It returns the user with the new profile;
// the same language is not written again.
func (s *AccountService) SetLocale(ctx context.Context, user *domain.User, locale string, ev AccountEvent) (*domain.User, error) {
	if current, _ := user.Profile["locale"].(string); current == locale {
		return user, nil
	}
	profile := maps.Clone(user.Profile)
	if profile == nil {
		profile = map[string]interface{}{}
	}
	profile["locale"] = locale
	if err := s.d.Admin.SetUserProfile(ctx, user.ID, profile); err != nil {
		return nil, fmt.Errorf("set locale: %w", err)
	}
	s.audit(ctx, user, audit.UserProfileUpdated, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"fields": []string{"locale"}, "locale": locale})
	out := *user
	out.Profile = profile
	return &out, nil
}

// cleanName trims a name and refuses what no name contains: control
// characters, more than maxNameLength characters.
func cleanName(v string) (string, error) {
	v = strings.Join(strings.Fields(v), " ")
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxNameLength {
		return "", ErrInvalidName
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "", ErrInvalidName
		}
	}
	return v, nil
}

// --- password --------------------------------------------------------------

// MinPasswordLength is the realm's minimum, shown on the "Change your
// password" page (ChangePassword checks it again).
func (s *AccountService) MinPasswordLength(ctx context.Context, realmID string) int {
	return s.d.Policy.MinLength(ctx, realmID)
}

type ChangePasswordInput struct {
	User      *domain.User
	SessionID string // the session in use: it stays signed in
	Current   string
	New       string
	Event     AccountEvent
}

type ChangePasswordResult struct {
	// SessionsEnded: the user's other sessions, signed out by the change.
	SessionsEnded int
}

// ChangePassword replaces the user's password after checking the current
// one. Every other session of the user ends (spec: "Changer votre mot de
// passe déconnectera immédiatement toutes vos autres sessions actives"),
// and the user gets the "password changed" e-mail.
func (s *AccountService) ChangePassword(ctx context.Context, in ChangePasswordInput) (*ChangePasswordResult, error) {
	user := in.User
	if user.PasswordHash == "" {
		return nil, ErrNoPassword
	}
	ok, err := verifyPassword(ctx, in.Current, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	if !ok {
		s.audit(ctx, user, audit.UserPasswordChanged, "User", user.ID, domain.AuditLogWarning, domain.AuditLogFailure, in.Event,
			map[string]interface{}{"reason": "wrong_current_password"})
		return nil, ErrWrongPassword
	}
	if in.New == in.Current {
		return nil, ErrPasswordUnchanged
	}
	if err := s.d.Policy.Validate(ctx, user.RealmID, in.New, user); err != nil {
		return nil, err
	}
	hash, err := HashPasswordContext(ctx, in.New)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	// Only if the password is still the one just checked: a password reset
	// finishing at the same moment wins.
	swapped, err := s.d.Users.CompareAndSwapPasswordHash(ctx, user.ID, user.PasswordHash, hash)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	if !swapped {
		return nil, ErrWrongPassword
	}
	// The hash is already written (compare-and-swap above): the change time,
	// the history and the end of a forced reset (signed in with a passkey)
	// follow.
	change := s.d.Policy.PasswordChange(ctx, user, hash, s.d.Now())
	change.PasswordHash = nil
	if user.MustChangePassword {
		changeDone := false
		change.MustChangePassword = &changeDone
	}
	if _, err := s.d.Users.Update(ctx, user.ID, change); err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	n, err := s.d.Sessions.RevokeOthers(ctx, user.ID, in.SessionID, domain.SessionRevokedPasswordChanged)
	if err != nil {
		return nil, fmt.Errorf("change password: sign out other sessions: %w", err)
	}
	s.audit(ctx, user, audit.UserPasswordChanged, "User", user.ID, domain.AuditLogWarning, domain.AuditLogSuccess, in.Event,
		map[string]interface{}{"sessions_ended": n})
	s.d.Notifier.Notify(ctx, domain.NotificationEvent{
		Kind:       domain.NotificationPasswordChanged,
		RealmID:    user.RealmID,
		UserID:     user.ID,
		OccurredAt: s.d.Now(),
		IPAddress:  in.Event.IPAddress,
		UserAgent:  in.Event.UserAgent,
	})
	return &ChangePasswordResult{SessionsEnded: n}, nil
}

// --- sessions --------------------------------------------------------------

// AccountSession is one row of the "Sessions" page.
// The JSON names are those of the copy of the user's data (account_export.go).
type AccountSession struct {
	ID             string    `json:"id"`
	Current        bool      `json:"-"` // the session of this browser
	Device         string    `json:"-"` // hash of the browser's sso_device cookie; "" when it had none
	IPAddress      string    `json:"ip_address"`
	Country        string    `json:"country,omitempty"`
	UserAgent      string    `json:"user_agent"`
	AuthMethod     string    `json:"auth_method"` // RFC 8176: pwd, hwk, swk, otp, mfa
	MFAVerified    bool      `json:"mfa_verified"`
	MFAMethod      string    `json:"mfa_method,omitempty"`
	RememberMe     bool      `json:"remember_me"`    // "Keep me signed in" was ticked
	TrustedDevice  bool      `json:"trusted_device"` // the second factor was skipped on a trusted device
	Apps           []string  `json:"applications"`
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Sessions lists the user's live sessions with the rules of the admin
// console (active, not expired, used within the realm's idle timeout): the
// current one first, then the most recently used.
func (s *AccountService) Sessions(ctx context.Context, user *domain.User, currentID string) ([]AccountSession, error) {
	live, err := s.liveSessions(ctx, user)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(live))
	for _, se := range live {
		ids = append(ids, se.ID)
	}
	clients, err := s.d.Admin.SessionClients(ctx, ids, s.d.Now())
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	names := map[string]string{}
	out := make([]AccountSession, 0, len(live))
	for _, se := range live {
		v := AccountSession{
			ID: se.ID, Current: se.ID == currentID, Device: se.DeviceFingerprint, IPAddress: se.IPAddress, Country: s.Country(se.IPAddress),
			UserAgent: se.UserAgent, AuthMethod: se.AuthMethod, MFAVerified: se.MFAVerified, MFAMethod: se.MFAMethodType,
			RememberMe: se.RememberMe, TrustedDevice: se.TrustedDevice,
			CreatedAt: se.CreatedAt, LastActivityAt: se.LastActivityAt, ExpiresAt: se.ExpiresAt,
		}
		for _, ref := range clients[se.ID] {
			name, ok := names[ref]
			if !ok {
				name = s.clientName(ctx, ref)
				names[ref] = name
			}
			if name != "" && !slices.Contains(v.Apps, name) {
				v.Apps = append(v.Apps, name)
			}
		}
		out = append(out, v)
	}
	slices.SortStableFunc(out, func(a, b AccountSession) int {
		switch {
		case a.Current != b.Current:
			if a.Current {
				return -1
			}
			return 1
		default:
			return b.LastActivityAt.Compare(a.LastActivityAt)
		}
	})
	return out, nil
}

// SessionsByDevice is Sessions with one row per browser: signing in again in
// the same browser opens a new session and keeps the old one (its
// applications' tokens are bound to it), which would show the device twice,
// often with an IPv4 and an IPv6 address. The row kept is the current session,
// else the most recently used; it lists the applications of the sessions it
// hides. RevokeSession ends them with it. Sessions without a device cookie
// are never merged.
func (s *AccountService) SessionsByDevice(ctx context.Context, user *domain.User, currentID string) ([]AccountSession, error) {
	all, err := s.Sessions(ctx, user, currentID)
	if err != nil {
		return nil, err
	}
	kept := map[string]int{} // device -> index in out
	out := make([]AccountSession, 0, len(all))
	for _, v := range all {
		i, seen := kept[v.Device]
		if v.Device == "" || !seen {
			if v.Device != "" {
				kept[v.Device] = len(out)
			}
			out = append(out, v)
			continue
		}
		for _, app := range v.Apps {
			if !slices.Contains(out[i].Apps, app) {
				out[i].Apps = append(out[i].Apps, app)
			}
		}
	}
	return out, nil
}

// liveSessions: the user's sessions that are still usable now.
func (s *AccountService) liveSessions(ctx context.Context, user *domain.User) ([]*domain.Session, error) {
	d := SessionDurationsOf(s.settings.get(ctx, user.RealmID))
	now := s.d.Now()
	win := repository.SessionSearch{RealmID: user.RealmID, UserID: user.ID, Now: now, IdleSince: now.Add(-d.IdleTimeout)}
	if d.RememberMe {
		win.RememberIdleSince = now.Add(-d.RememberMeIdleTimeout)
	} else {
		win.RememberIdleSince = win.IdleSince
		win.RememberCreatedSince = now.Add(-d.MaxLifetime)
	}
	win.Page = repository.Page{Limit: maxAccountSessions, NoTotal: true}
	sessions, _, err := s.d.Admin.SearchSessions(ctx, win)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

func (s *AccountService) clientName(ctx context.Context, ref string) string {
	c, err := s.d.Clients.GetByID(ctx, ref)
	if err != nil {
		return ""
	}
	return clientDisplayName(c)
}

// RevokeSession signs one of the user's other sessions out, with the tokens
// its applications hold. The session in use is refused: "Sign out" does
// that.
func (s *AccountService) RevokeSession(ctx context.Context, user *domain.User, currentID, sessionID string, ev AccountEvent) error {
	if sessionID == currentID {
		return ErrCurrentSession
	}
	se, err := s.d.Sessions.GetActive(ctx, sessionID)
	if errors.Is(err, ErrSessionInvalid) || (err == nil && se.UserID != user.ID) {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if err := s.d.Sessions.Revoke(ctx, se.ID, domain.SessionRevokedByUser); err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("revoke session: %w", err)
	}
	err = s.revokeSameDevice(ctx, user, currentID, se)
	s.audit(ctx, user, audit.SessionRevoked, "Session", se.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev, nil)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// revokeSameDevice ends the sessions SessionsByDevice hides behind the row of
// se: a row signed out must not leave a usable session of the same browser.
// Every session is tried whatever the others do.
func (s *AccountService) revokeSameDevice(ctx context.Context, user *domain.User, currentID string, se *domain.Session) error {
	if se.DeviceFingerprint == "" {
		return nil
	}
	live, err := s.liveSessions(ctx, user)
	errs := []error{err}
	for _, old := range live {
		if old.ID == se.ID || old.ID == currentID || old.DeviceFingerprint != se.DeviceFingerprint {
			continue
		}
		if err := s.d.Sessions.Revoke(ctx, old.ID, domain.SessionRevokedByUser); !errors.Is(err, ErrSessionInvalid) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RevokeOtherSessions signs out every session of the user but currentID,
// and tells how many.
func (s *AccountService) RevokeOtherSessions(ctx context.Context, user *domain.User, currentID string, ev AccountEvent) (int, error) {
	n, err := s.d.Sessions.RevokeOthers(ctx, user.ID, currentID, domain.SessionRevokedByUser)
	if err != nil {
		return n, err
	}
	s.audit(ctx, user, audit.SessionRevokedAll, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"count": n})
	return n, nil
}

// --- connected applications ------------------------------------------------

// AccountApp is one row of the "Connected apps" page: an application the
// user approved (consent screen), or one holding a live token for one of
// the user's sessions (applications without a consent screen).
type AccountApp struct {
	ClientRef string `json:"-"`
	Name      string `json:"name"`
	// Host: where the application lives (host of its redirect URI or of
	// its SAML ACS URL), so that a look-alike name can be told apart.
	Host string `json:"host,omitempty"`
	// Consent: the user approved it on the consent screen; Scopes and
	// GrantedAt describe that approval.
	Consent   bool       `json:"consent"`
	Scopes    []AppScope `json:"scopes,omitempty"`
	GrantedAt time.Time  `json:"granted_at,omitzero"`
	// SignedIn: it holds a live token for one of the user's sessions now.
	SignedIn bool `json:"signed_in"`
}

// AppScope: one thing the application may read. Description is the
// realm's description of a custom scope; the HTTP layer words the standard
// ones (profile, email, offline_access).
type AppScope struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (s *AccountService) Apps(ctx context.Context, user *domain.User) ([]AccountApp, error) {
	byRef := map[string]*AccountApp{}
	consents, err := s.d.Consents.List(ctx, user.RealmID, user.ID)
	if err != nil {
		return nil, err
	}
	for _, cv := range consents {
		if !cv.Consent.IsGranted() || cv.Client == nil || cv.Client.IsDeleted() {
			continue
		}
		app := s.appOf(cv.Client)
		app.Consent, app.GrantedAt = true, cv.Consent.GrantedAt
		app.Scopes = s.describeScopes(ctx, user.RealmID, cv.Consent.Scopes)
		byRef[cv.Client.ID] = app
	}

	live, err := s.liveSessions(ctx, user)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(live))
	for _, se := range live {
		ids = append(ids, se.ID)
	}
	clients, err := s.d.Admin.SessionClients(ctx, ids, s.d.Now())
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	for _, refs := range clients {
		for _, ref := range refs {
			if app, ok := byRef[ref]; ok {
				app.SignedIn = true
				continue
			}
			c, err := s.d.Clients.GetByID(ctx, ref)
			if err != nil || c.RealmID != user.RealmID || c.IsDeleted() {
				continue
			}
			app := s.appOf(c)
			app.SignedIn = true
			byRef[ref] = app
		}
	}

	out := make([]AccountApp, 0, len(byRef))
	for _, app := range byRef {
		out = append(out, *app)
	}
	slices.SortFunc(out, func(a, b AccountApp) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

func (s *AccountService) appOf(c *domain.ClientApp) *AccountApp {
	app := &AccountApp{ClientRef: c.ID, Name: clientDisplayName(c)}
	raw := c.ACSURL
	if c.Protocol == domain.ClientAppProtocolOIDC && len(c.RedirectURIs) > 0 {
		raw = c.RedirectURIs[0]
	}
	if u, err := url.Parse(raw); err == nil {
		app.Host = u.Hostname()
	}
	return app
}

// describeScopes: "openid" says nothing to a person (signing in is the
// point of the application); the others keep their realm description.
func (s *AccountService) describeScopes(ctx context.Context, realmID string, scopes []string) []AppScope {
	out := make([]AppScope, 0, len(scopes))
	for _, name := range scopes {
		if name == "openid" {
			continue
		}
		sc := AppScope{Name: name}
		if s.d.ClientScopes != nil {
			if cs, err := s.d.ClientScopes.GetByRealmAndName(ctx, realmID, name); err == nil {
				sc.Description = strings.TrimSpace(cs.Description)
			}
		}
		out = append(out, sc)
	}
	return out
}

type RevokeAppResult struct {
	TokensRevoked int
}

// RevokeApp takes back an application's access: its consent (the consent
// screen shows again next time) and every token it holds for the user.
// An application without consent screen loses its tokens: it signs the
// user out, but signing in again works without a question, since the
// user is still signed in here.
func (s *AccountService) RevokeApp(ctx context.Context, user *domain.User, clientRef string, ev AccountEvent) (*RevokeAppResult, error) {
	c, err := s.d.Clients.GetByID(ctx, clientRef)
	if err != nil || c.RealmID != user.RealmID {
		return nil, ErrAppNotFound
	}
	res, err := s.d.Consents.Revoke(ctx, RevokeConsentInput{
		RealmID: user.RealmID, UserID: user.ID, ClientRef: c.ID,
		Actor: PolicyActor{TriggeredBy: "user:" + user.ID}, Reason: "account_console",
	})
	switch {
	case err == nil:
		return &RevokeAppResult{TokensRevoked: res.TokensRevoked}, nil // ConsentService wrote "consent.revoked"
	case !errors.Is(err, ErrConsentNotFound):
		return nil, err
	}
	n, err := s.d.Tokens.RevokeByUserAndClient(ctx, user.ID, c.ID)
	if err != nil {
		return nil, fmt.Errorf("revoke app: %w", err)
	}
	if n == 0 {
		return nil, ErrAppNotFound
	}
	s.audit(ctx, user, audit.ConsentAppAccessRevoked, "ClientApp", c.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"client": clientDisplayName(c), "tokens_revoked": n})
	return &RevokeAppResult{TokensRevoked: n}, nil
}

// --- trusted devices -------------------------------------------------------

// TrustedDevices: the devices where the user ticked "Don't ask again on
// this device", most recent first.
func (s *AccountService) TrustedDevices(ctx context.Context, user *domain.User) ([]*domain.TrustedDevice, error) {
	if s.d.TrustedDevices == nil {
		return nil, nil
	}
	return s.d.TrustedDevices.List(ctx, user.ID)
}

// RevokeTrustedDevice: the device asks for the second factor again.
func (s *AccountService) RevokeTrustedDevice(ctx context.Context, user *domain.User, id string, ev AccountEvent) error {
	if s.d.TrustedDevices == nil {
		return ErrTrustedDeviceNotFound
	}
	if err := s.d.TrustedDevices.RevokeOne(ctx, user.ID, id); err != nil {
		return err
	}
	s.audit(ctx, user, audit.TrustedDeviceRevoked, "TrustedDevice", id, domain.AuditLogInfo, domain.AuditLogSuccess, ev, nil)
	return nil
}

// RevokeTrustedDevices: every device asks for the second factor again.
func (s *AccountService) RevokeTrustedDevices(ctx context.Context, user *domain.User, ev AccountEvent) (int, error) {
	if s.d.TrustedDevices == nil {
		return 0, nil
	}
	n, err := s.d.TrustedDevices.RevokeAll(ctx, user.ID)
	if err != nil {
		return 0, err
	}
	s.audit(ctx, user, audit.TrustedDeviceRevokedAll, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"count": n})
	return n, nil
}

// --- history ---------------------------------------------------------------

// SignInEntry is one sign-in attempt on the user's account.
type SignInEntry struct {
	At        time.Time                        `json:"at"`
	IPAddress string                           `json:"ip_address"`
	Country   string                           `json:"country,omitempty"`
	UserAgent string                           `json:"user_agent"`
	Success   bool                             `json:"success"`
	Reason    domain.LoginAttemptFailureReason `json:"failure_reason,omitempty"`
}

// SignIns returns one page of the user's sign-in attempts, newest first,
// and whether older ones exist.
func (s *AccountService) SignIns(ctx context.Context, user *domain.User, offset, limit int) ([]SignInEntry, bool, error) {
	rows, err := s.d.LoginAttempts.ListByUser(ctx, user.ID, repository.Page{Offset: offset, Limit: limit + 1})
	if err != nil {
		return nil, false, fmt.Errorf("sign-in history: %w", err)
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]SignInEntry, 0, len(rows))
	for _, a := range rows {
		if a.RealmID != "" && a.RealmID != user.RealmID {
			continue
		}
		out = append(out, SignInEntry{
			At: a.CreatedAt, IPAddress: a.IPAddress, Country: s.Country(a.IPAddress), UserAgent: a.UserAgent,
			Success: a.Status == domain.LoginAttemptSuccess, Reason: a.FailureReason,
		})
	}
	return out, more, nil
}

// AccountActivityActions: the audit entries the "Account activity" list
// shows (the HTTP layer words each of them). The others (notifications
// sent, sign-ins, which have their own list...) are not about something
// the user would recognise.
var AccountActivityActions = []string{
	// by the user (some also by an administrator, or the server)
	audit.UserProfileUpdated, audit.UserPasswordChanged, audit.SessionRevoked, audit.SessionRevokedAll,
	audit.ConsentAppAccessRevoked, audit.TrustedDeviceRevoked, audit.TrustedDeviceRevokedAll,
	audit.MFAMethodEnrolled, audit.MFAMethodRemoved, audit.MFABackupCodesRegenerated,
	audit.TrustedDeviceAdded,
	audit.ConsentGranted, audit.ConsentRevoked, audit.KnownAccountForgotten,
	audit.UserDataExportRequested, audit.UserDataExported, audit.UserDeletionRequested, audit.UserDeletionCancelled,
	audit.UserEmailChangeRequested, audit.UserEmailChanged, audit.UserEmailChangeCancelled,
	audit.UserPasswordResetRequested, audit.UserPasswordReset, audit.UserLocked,
	// by an administrator, about the user
	audit.UserInvited, audit.UserActivationLinkSent, audit.UserUpdated, audit.UserGroupsChanged, audit.UserRolesChanged,
	audit.MFAReset, audit.UserUnlocked,
}

// ActivityEntry is one entry of the "Account activity" list.
type ActivityEntry struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	// ByAdmin: an administrator did it (their name and address are not
	// shown to the user).
	ByAdmin   bool                   `json:"by_administrator"`
	IPAddress string                 `json:"ip_address,omitempty"` // empty when ByAdmin
	UserAgent string                 `json:"user_agent,omitempty"` // empty when ByAdmin
	Failed    bool                   `json:"failed"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Activity returns one page of what happened to the account, newest first,
// and whether older entries exist.
func (s *AccountService) Activity(ctx context.Context, user *domain.User, offset, limit int) ([]ActivityEntry, bool, error) {
	return s.activity(ctx, user, AccountActivityActions, offset, limit)
}

// activity: Activity with any of these actions (nil: every action). An
// entry the user wrote about someone else is left out: it is that person's
// data, not theirs.
func (s *AccountService) activity(ctx context.Context, user *domain.User, actions []string, offset, limit int) ([]ActivityEntry, bool, error) {
	rows, _, err := s.d.Admin.SearchAuditLogs(ctx, repository.AuditSearch{
		RealmID: user.RealmID, UserID: user.ID, Actions: actions,
		Page: repository.Page{Offset: offset, Limit: limit + 1, NoTotal: true},
	})
	if err != nil {
		return nil, false, fmt.Errorf("account activity: %w", err)
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]ActivityEntry, 0, len(rows))
	for _, r := range rows {
		// Only what is about the account: an entry the user wrote as an
		// administrator about nobody (an import, a bulk action) holds other
		// people's data. Normalized sets the target of any entry on a user.
		if r.TargetUserID != user.ID {
			continue
		}
		e := ActivityEntry{At: r.Timestamp, Action: r.Action, Failed: r.Status == domain.AuditLogFailure, Details: r.Details}
		if r.ActorType == domain.AuditActorAdmin || r.ActorType == domain.AuditActorCLI || (r.UserID != "" && r.UserID != user.ID) {
			e.ByAdmin = true
			e.Details = withoutKeys(r.Details, operatorKeys...)
		} else {
			e.IPAddress, e.UserAgent = r.IPAddress, r.UserAgent
		}
		if e.Details == nil {
			e.Details = map[string]interface{}{}
		}
		out = append(out, e)
	}
	return out, more, nil
}

// operatorKeys name who acted for the organization (auditAdminAbout,
// writeCLIAudit): the user sees that an administrator did it, not who.
var operatorKeys = []string{"admin_username", "admin_realm", "triggered_by"}

// withoutKeys copies m without keys (m is the stored row's: never changed).
func withoutKeys(m map[string]interface{}, keys ...string) map[string]interface{} {
	out := maps.Clone(m)
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

// --- helpers ---------------------------------------------------------------

func (s *AccountService) audit(ctx context.Context, user *domain.User, action, resourceType, resourceID string,
	level domain.AuditLogLevel, status domain.AuditLogStatus, ev AccountEvent, details map[string]interface{}) {
	if s.d.Audit == nil {
		return
	}
	if _, err := s.d.Audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID: user.RealmID, UserID: user.ID, ActorType: domain.AuditActorUser, TargetUserID: user.ID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID,
		IPAddress: ev.IPAddress, UserAgent: ev.UserAgent,
		Level: level, Status: status, Details: details,
	}); err != nil {
		s.d.Logger.WarnContext(ctx, "account: audit", "action", action, "user_id", user.ID, "error", err)
	}
}
