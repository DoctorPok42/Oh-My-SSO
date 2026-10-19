package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Session participants (Step 11).
//
// A SAML service provider keeps its own session once it has accepted an
// assertion. For Single Logout the IdP must remember, per IdP session, which
// service providers got an assertion, with the NameID and SessionIndex they
// received: a LogoutRequest sent to them must repeat both. Those facts are
// stored as Token rows of type "saml_session", next to the OIDC tokens of
// the same session, so the existing cascade (RevokeSession revokes every
// token of the session) covers them too.

func (s *IdentityCoreService) RegisterSessionParticipant(ctx context.Context, p core.SessionParticipant) (*domain.Token, error) {
	if p.SessionID == "" || p.ClientRef == "" || p.Subject == "" {
		return nil, fmt.Errorf("register session participant: session, client and subject are required")
	}
	sess, err := s.sessions.GetActive(ctx, p.SessionID)
	if err != nil {
		return nil, err
	}
	client, err := s.clients.GetByID(ctx, p.ClientRef)
	if err != nil {
		return nil, fmt.Errorf("register session participant: load client: %w", err)
	}
	if client.RealmID != sess.RealmID || client.IsDeleted() || client.Status != domain.ClientAppActive {
		return nil, core.ErrClientNotFound
	}

	toks, err := s.tokens.ListBySession(ctx, sess.ID)
	if err != nil {
		return nil, fmt.Errorf("register session participant: list tokens: %w", err)
	}
	now := s.now()
	for _, t := range toks {
		if t.Type != domain.TokenSAMLSession || t.Revoked || t.ClientRefID != client.ID || !t.ExpiresAt.After(now) {
			continue
		}
		if t.SubjectFormat != p.SubjectFormat {
			continue // the client's configuration changed: a new record
		}
		// A transient NameID is random (SAML Core §8.3.8): keep the first one
		// for the whole session. Any other format must give the same value.
		if p.SubjectFormat == domain.NameIDFormatTransient || t.Subject == p.Subject {
			return t, nil
		}
	}

	return s.tokens.Create(ctx, repository.CreateTokenParams{
		SessionID:   sess.ID,
		ClientRefID: client.ID,
		Type:        domain.TokenSAMLSession,
		// The SessionIndex the client will know. Random and unguessable: it
		// is part of what identifies a session in a LogoutRequest.
		JTI:           "_" + rand.Text(),
		ExpiresAt:     sess.ExpiresAt,
		Subject:       p.Subject,
		SubjectFormat: p.SubjectFormat,
	})
}

func (s *IdentityCoreService) SessionParticipants(ctx context.Context, sessionID string) ([]*domain.Token, error) {
	toks, err := s.tokens.ListBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session participants: %w", err)
	}
	out := make([]*domain.Token, 0, len(toks))
	for _, t := range toks {
		if t.Type == domain.TokenSAMLSession && !t.Revoked {
			out = append(out, t)
		}
	}
	slices.SortStableFunc(out, func(a, b *domain.Token) int { return a.IssuedAt.Compare(b.IssuedAt) })
	return out, nil
}
