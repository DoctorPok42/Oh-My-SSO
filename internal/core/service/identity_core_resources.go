package service

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// API resources (RFC 8707): a client names the API it wants a token for with
// "resource"; the access token's "aud" is then that API, and it keeps only
// the API's scopes (plus the standard OIDC ones), so another API refuses it.

func (s *IdentityCoreService) CheckResources(ctx context.Context, realmID string, held []*domain.ClientScope, identifiers []string) ([]string, error) {
	if len(identifiers) == 0 {
		return nil, nil
	}
	return s.allowedResources(ctx, realmID, identifiers, held)
}

// allowedResources: each identifier must be an API resource of the realm
// sharing at least one scope with held (the scopes the client may get).
// Without duplicates, in order.
func (s *IdentityCoreService) allowedResources(ctx context.Context, realmID string, identifiers []string, held []*domain.ClientScope) ([]string, error) {
	out := []string{}
	for _, id := range identifiers {
		if slices.Contains(out, id) {
			continue
		}
		res, err := s.resource(ctx, realmID, id)
		if err != nil {
			return nil, err
		}
		shared := slices.ContainsFunc(res.Scopes, func(cs *domain.ClientScope) bool {
			return slices.ContainsFunc(held, func(h *domain.ClientScope) bool { return h.ID == cs.ID })
		})
		if !shared {
			return nil, fmt.Errorf("%w: the client may not ask for %q", core.ErrInvalidTarget, id)
		}
		out = append(out, id)
	}
	return out, nil
}

func (s *IdentityCoreService) resource(ctx context.Context, realmID, identifier string) (*domain.ApiResource, error) {
	if s.resources == nil {
		return nil, fmt.Errorf("%w: unknown resource %q", core.ErrInvalidTarget, identifier)
	}
	res, err := s.resources.GetByRealmAndIdentifier(ctx, realmID, identifier)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown resource %q", core.ErrInvalidTarget, identifier)
	}
	if err != nil {
		return nil, fmt.Errorf("resource %q: %w", identifier, err)
	}
	return res, nil
}

// tokenGrant is what one issuance gives: the refresh token keeps the grant
// (scopes, resources), the access token gets accessScopes for audience.
type tokenGrant struct {
	scopes, resources      []string
	accessScopes, audience []string
}

// newTokenGrant picks the access token's audience among the grant's
// resources (RFC 8707, section 2.2): those asked, each one granted, else all
// of them. With an audience, the access token keeps the standard OIDC scopes
// and those of its resources only. A resource deleted since the grant is
// ErrInvalidTarget.
func (s *IdentityCoreService) newTokenGrant(ctx context.Context, realmID string, scopes, resources, asked []string) (tokenGrant, error) {
	g := tokenGrant{scopes: orEmpty(scopes), resources: resources, accessScopes: orEmpty(scopes), audience: resources}
	if len(asked) > 0 {
		g.audience = nil
		for _, id := range asked {
			if !slices.Contains(resources, id) {
				return tokenGrant{}, fmt.Errorf("%w: %q is not part of the grant", core.ErrInvalidTarget, id)
			}
			g.audience = appendUnique(g.audience, id)
		}
	}
	if len(g.audience) == 0 {
		return g, nil
	}
	keep := slices.Clone(StandardOIDCScopes)
	for _, id := range g.audience {
		res, err := s.resource(ctx, realmID, id)
		if err != nil {
			return tokenGrant{}, err
		}
		for _, cs := range res.Scopes {
			keep = append(keep, cs.Name)
		}
	}
	g.accessScopes = []string{}
	for _, sc := range g.scopes {
		if slices.Contains(keep, sc) {
			g.accessScopes = append(g.accessScopes, sc)
		}
	}
	return g, nil
}
