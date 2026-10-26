package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


var (
	// ErrConsentNotFound: the user never approved this client.
	ErrConsentNotFound = errors.New("service: no consent for this user and client")
)

// ConsentSessions is the part of SessionService the consent service needs:
// the session proves which user is answering.
type ConsentSessions interface {
	GetActive(ctx context.Context, sessionID string) (*domain.Session, error)
}

// ConsentDeps groups the dependencies of NewConsentService.
type ConsentDeps struct {
	Consents repository.ConsentRepository
	Clients  repository.ClientRepository
	Sessions ConsentSessions
	// Tokens: revoking a consent also revokes the tokens of that client.
	Tokens repository.TokenRepository
	// Audit: consent_granted, consent_denied, consent_revoked,
	// consent_policy_changed. nil: nothing is audited (tests).
	Audit repository.AuditLogRepository
	// Notifier: the "an application can access your account" e-mail.
	// nil: NopNotifier.
	Notifier Notifier
	Logger   *slog.Logger
}

type ConsentService struct {
	consents repository.ConsentRepository
	clients  repository.ClientRepository
	sessions ConsentSessions
	tokens   repository.TokenRepository
	audit    repository.AuditLogRepository
	notifier Notifier
	logger   *slog.Logger
	now      func() time.Time
}

type ConsentOption func(*ConsentService)

// WithConsentClock injects a fake clock (tests).
func WithConsentClock(now func() time.Time) ConsentOption {
	return func(s *ConsentService) { s.now = now }
}

func NewConsentService(d ConsentDeps, opts ...ConsentOption) *ConsentService {
	s := &ConsentService{
		consents: d.Consents,
		clients:  d.Clients,
		sessions: d.Sessions,
		tokens:   d.Tokens,
		audit:    d.Audit,
		notifier: d.Notifier,
		logger:   d.Logger,
		now:      time.Now,
	}
	if s.notifier == nil {
		s.notifier = NopNotifier{}
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ConsentRequired is the decision itself, with nothing to read: given the
// client's setting, what the user approved before (nil: never) and the
// scopes about to be released, must the user be asked?
//
//	force (prompt=consent)                  -> yes, always
//	require_consent = false                 -> no, never
//	no consent, or a revoked one            -> yes (first use of the client)
//	a scope not approved yet                -> yes, the new ones are Missing
//	every scope approved before             -> no
func ConsentRequired(requireConsent bool, stored *domain.Consent, scopes []string, force bool) core.ConsentDecision {
	var missing []string
	for _, sc := range normalizeScopes(scopes) {
		if !stored.IsGranted() || !slices.Contains(stored.Scopes, sc) {
			missing = append(missing, sc)
		}
	}
	d := core.ConsentDecision{Missing: missing, Previously: stored.IsGranted()}
	switch {
	case force:
		d.Required = true
	case !requireConsent:
		d.Required = false
	default:
		d.Required = !stored.IsGranted() || len(missing) > 0
	}
	return d
}

// Check implements IdentityCore.CheckConsent.
func (s *ConsentService) Check(ctx context.Context, c core.ConsentCheck) (*core.ConsentDecision, error) {
	sess, client, err := s.sessionAndClient(ctx, c.SessionID, c.ClientRef)
	if err != nil {
		return nil, err
	}
	if !client.RequireConsent && !c.Force {
		// The common case (trusted, internal applications): no database read.
		return &core.ConsentDecision{}, nil
	}
	stored, err := s.stored(ctx, sess.UserID, client.ID)
	if err != nil {
		return nil, err
	}
	d := ConsentRequired(client.RequireConsent, stored, c.Scopes, c.Force)
	return &d, nil
}

// Grant implements IdentityCore.GrantConsent.
func (s *ConsentService) Grant(ctx context.Context, g core.ConsentGrant) (*domain.Consent, error) {
	sess, client, err := s.sessionAndClient(ctx, g.SessionID, g.ClientRef)
	if err != nil {
		return nil, err
	}
	scopes := make([]string, 0, len(g.Items))
	for _, it := range g.Items {
		scopes = append(scopes, it.Scope)
	}
	scopes = normalizeScopes(scopes)

	stored, err := s.stored(ctx, sess.UserID, client.ID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		created, err := s.consents.Create(ctx, repository.CreateConsentParams{
			UserID: sess.UserID, ClientRefID: client.ID, Scopes: scopes,
		})
		switch {
		case err == nil:
			s.granted(ctx, sess, client, g, created, scopes, false)
			return created, nil
		case errors.Is(err, repository.ErrConflict):
			// Another tab approved the same client a moment ago: merge
			// into the row it created.
			if stored, err = s.stored(ctx, sess.UserID, client.ID); err != nil {
				return nil, err
			}
			if stored == nil {
				return nil, fmt.Errorf("grant consent: row vanished after a conflict")
			}
		default:
			return nil, fmt.Errorf("grant consent: %w", err)
		}
	}

	if !stored.IsGranted() {
		// Approved again after a revocation: a fresh start. The scopes
		// approved before the revocation do not come back on their own.
		status, now := domain.ConsentGranted, s.now()
		updated, err := s.consents.Update(ctx, stored.ID, repository.UpdateConsentParams{
			Scopes: nonNilScopes(scopes), Status: &status, GrantedAt: &now, ClearRevokedAt: true,
		})
		if err != nil {
			return nil, fmt.Errorf("grant consent: %w", err)
		}
		s.granted(ctx, sess, client, g, updated, scopes, false)
		return updated, nil
	}

	var added []string
	for _, sc := range scopes {
		if !slices.Contains(stored.Scopes, sc) {
			added = append(added, sc)
		}
	}
	if len(added) == 0 {
		return stored, nil // nothing new: no write, no e-mail
	}
	merged := append(slices.Clone(stored.Scopes), added...)
	updated, err := s.consents.Update(ctx, stored.ID, repository.UpdateConsentParams{Scopes: merged})
	if err != nil {
		return nil, fmt.Errorf("grant consent: %w", err)
	}
	s.granted(ctx, sess, client, g, updated, added, true)
	return updated, nil
}

// granted writes the AuditLog entry and sends the e-mail. added: the scopes
// this approval brought; expanded: the client already had access before.
func (s *ConsentService) granted(ctx context.Context, sess *domain.Session, client *domain.ClientApp,
	g core.ConsentGrant, c *domain.Consent, added []string, expanded bool) {
	s.writeAudit(ctx, repository.CreateAuditLogParams{
		RealmID: sess.RealmID, UserID: sess.UserID, Action: "consent_granted",
		ResourceType: "Consent", ResourceID: c.ID, IPAddress: g.IPAddress, UserAgent: g.UserAgent,
		Level: domain.AuditLogInfo, Status: domain.AuditLogSuccess,
		Details: map[string]interface{}{
			"client_ref": client.ID, "client": clientDisplayName(client),
			"scopes": c.Scopes, "added": added, "expanded": expanded,
		},
	})
	var access []string
	for _, it := range g.Items {
		if slices.Contains(added, it.Scope) && it.Title != "" && !slices.Contains(access, it.Title) {
			access = append(access, it.Title)
		}
	}
	s.notifier.Notify(ctx, domain.NotificationEvent{
		Kind: domain.NotificationAppConnected, RealmID: sess.RealmID, UserID: sess.UserID,
		OccurredAt: s.now(), IPAddress: g.IPAddress, UserAgent: g.UserAgent,
		ClientName: clientDisplayName(client), Access: access, AccessAdded: expanded,
	})
}

// Deny implements IdentityCore.DenyConsent: nothing is stored, the client
// can ask again (and the user can say yes next time).
func (s *ConsentService) Deny(ctx context.Context, d core.ConsentDenial) error {
	sess, client, err := s.sessionAndClient(ctx, d.SessionID, d.ClientRef)
	if err != nil {
		return err
	}
	s.writeAudit(ctx, repository.CreateAuditLogParams{
		RealmID: sess.RealmID, UserID: sess.UserID, Action: "consent_denied",
		ResourceType: "ClientApp", ResourceID: client.ID, IPAddress: d.IPAddress, UserAgent: d.UserAgent,
		Level: domain.AuditLogInfo, Status: domain.AuditLogFailure,
		Details: map[string]interface{}{"client": clientDisplayName(client), "scopes": normalizeScopes(d.Scopes)},
	})
	return nil
}


type ConsentView struct {
	Consent *domain.Consent
	Client  *domain.ClientApp
}

// List returns the consents of a user of the realm, granted or revoked.
func (s *ConsentService) List(ctx context.Context, realmID, userID string) ([]ConsentView, error) {
	rows, err := s.consents.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	out := make([]ConsentView, 0, len(rows))
	for _, c := range rows {
		client, err := s.clients.GetByID(ctx, c.ClientRefID)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			client = nil
		case err != nil:
			return nil, fmt.Errorf("list consents: client: %w", err)
		case client.RealmID != realmID:
			continue // never show another realm's data
		}
		out = append(out, ConsentView{Consent: c, Client: client})
	}
	return out, nil
}

// RevokeConsentInput: who takes back which consent, and why.
type RevokeConsentInput struct {
	RealmID   string
	UserID    string
	ClientRef string // ClientApp.ID
	Actor     PolicyActor
	Reason    string
}

// RevokeConsentResult tells what happened.
type RevokeConsentResult struct {
	Consent *domain.Consent
	// TokensRevoked: access, refresh and ID tokens of the client for this
	// user that were still active.
	TokensRevoked int
}

// Revoke takes a consent back: the row is marked revoked, and every token
// the client holds for the user is revoked with it (spec-panel-user.md,
// "Révoquer l'accès"), so a refresh token cannot keep the access alive. The
// next sign-in to the client shows the consent screen again. Revoking twice
// is not an error.
func (s *ConsentService) Revoke(ctx context.Context, in RevokeConsentInput) (*RevokeConsentResult, error) {
	client, err := s.clients.GetByID(ctx, in.ClientRef)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrConsentNotFound
		}
		return nil, fmt.Errorf("revoke consent: %w", err)
	}
	if client.RealmID != in.RealmID {
		return nil, ErrConsentNotFound
	}
	c, err := s.stored(ctx, in.UserID, client.ID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrConsentNotFound
	}
	if c.IsGranted() {
		if err := s.consents.Revoke(ctx, c.ID); err != nil {
			return nil, fmt.Errorf("revoke consent: %w", err)
		}
		c.Status, c.RevokedAt = domain.ConsentRevoked, s.now()
	}
	n := 0
	if s.tokens != nil {
		if n, err = s.tokens.RevokeByUserAndClient(ctx, in.UserID, client.ID); err != nil {
			return nil, fmt.Errorf("revoke consent: tokens: %w", err)
		}
	}
	s.writeAudit(ctx, repository.CreateAuditLogParams{
		RealmID: in.RealmID, UserID: userIDFromTrigger(in.Actor.TriggeredBy), Action: "consent_revoked",
		ResourceType: "Consent", ResourceID: c.ID,
		Level: domain.AuditLogInfo, Status: domain.AuditLogSuccess,
		Details: map[string]interface{}{
			"user_id": in.UserID, "client_ref": client.ID, "client": clientDisplayName(client),
			"tokens_revoked": n, "reason": in.Reason, "triggered_by": in.Actor.TriggeredBy,
		},
	})
	return &RevokeConsentResult{Consent: c, TokensRevoked: n}, nil
}

// SetClientConsentInput switches require_consent on or off for one client.
type SetClientConsentInput struct {
	RealmID   string
	ClientRef string // ClientApp.ID
	Required  bool
	Actor     PolicyActor
}

// SetClientRequirement changes ClientApp.require_consent. Turning it off does
// not delete the consents already given: turning it on again reuses them.
func (s *ConsentService) SetClientRequirement(ctx context.Context, in SetClientConsentInput) (*domain.ClientApp, error) {
	client, err := s.clients.GetByID(ctx, in.ClientRef)
	if err != nil {
		return nil, fmt.Errorf("set client consent: %w", err)
	}
	if client.RealmID != in.RealmID {
		return nil, fmt.Errorf("set client consent: %w", repository.ErrNotFound)
	}
	if client.ManagedBy == domain.ClientAppManagedByConfig && !in.Actor.FromConfig {
		return nil, ErrManagedByConfig
	}
	required := in.Required
	updated, err := s.clients.Update(ctx, client.ID, repository.UpdateClientAppParams{RequireConsent: &required})
	if err != nil {
		return nil, fmt.Errorf("set client consent: %w", err)
	}
	s.writeAudit(ctx, repository.CreateAuditLogParams{
		RealmID: in.RealmID, UserID: userIDFromTrigger(in.Actor.TriggeredBy), Action: "consent_policy_changed",
		ResourceType: "ClientApp", ResourceID: client.ID,
		Level: domain.AuditLogWarning, Status: domain.AuditLogSuccess,
		Details: map[string]interface{}{"require_consent": updated.RequireConsent, "triggered_by": in.Actor.TriggeredBy},
	})
	return updated, nil
}

// --- helpers -------------------------------------------------------------------

// sessionAndClient loads the active session and checks the client belongs
// to the same realm: a user can only answer for themselves, in their realm.
func (s *ConsentService) sessionAndClient(ctx context.Context, sessionID, clientRef string) (*domain.Session, *domain.ClientApp, error) {
	sess, err := s.sessions.GetActive(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	client, err := s.clients.GetByID(ctx, clientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, core.ErrClientNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("consent: load client: %w", err)
	}
	if client.RealmID != sess.RealmID || client.IsDeleted() {
		return nil, nil, core.ErrClientNotFound
	}
	return sess, client, nil
}

// stored returns the user's consent row for the client, or nil.
func (s *ConsentService) stored(ctx context.Context, userID, clientRef string) (*domain.Consent, error) {
	c, err := s.consents.GetByUserAndClient(ctx, userID, clientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("consent: load: %w", err)
	}
	return c, nil
}

func (s *ConsentService) writeAudit(ctx context.Context, p repository.CreateAuditLogParams) {
	if s.audit == nil {
		return
	}
	if _, err := s.audit.Create(ctx, p); err != nil {
		s.logger.WarnContext(ctx, "consent: audit log write failed", "action", p.Action, "error", err)
	}
}

// normalizeScopes drops empty and repeated names, keeping the first order.
func normalizeScopes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// nonNilScopes: the repository treats a nil slice as "leave unchanged".
func nonNilScopes(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// clientDisplayName: the name users see (consent screen, e-mails), else its protocol id.
func clientDisplayName(c *domain.ClientApp) string {
	switch {
	case c.Name != "":
		return c.Name
	case c.ClientID != "":
		return c.ClientID
	case c.EntityID != "":
		return c.EntityID
	}
	return c.ID
}
