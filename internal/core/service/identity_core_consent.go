package service

import (
	"context"
	"errors"
	"fmt"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)


func (s *IdentityCoreService) CheckConsent(ctx context.Context, c core.ConsentCheck) (*core.ConsentDecision, error) {
	if s.consent != nil {
		return s.consent.Check(ctx, c)
	}
	if c.Force {
		return nil, core.ErrConsentNotConfigured
	}
	client, err := s.clients.GetByID(ctx, c.ClientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, core.ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("check consent: %w", err)
	}
	if client.RequireConsent {
		return nil, core.ErrConsentNotConfigured
	}
	return &core.ConsentDecision{}, nil
}

func (s *IdentityCoreService) GrantConsent(ctx context.Context, g core.ConsentGrant) (*domain.Consent, error) {
	if s.consent == nil {
		return nil, core.ErrConsentNotConfigured
	}
	return s.consent.Grant(ctx, g)
}

func (s *IdentityCoreService) DenyConsent(ctx context.Context, d core.ConsentDenial) error {
	if s.consent == nil {
		return core.ErrConsentNotConfigured
	}
	return s.consent.Deny(ctx, d)
}
