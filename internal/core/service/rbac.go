package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

var ErrForbidden = core.ErrForbidden // alias: same variable as core

const auditActionAuthorizationDenied = "authorization_denied"

const (
	denyUserNotFound     = "user_not_found"
	denyUserNotActive    = "user_not_active"
	denyClientNotFound   = "client_not_found"
	denyClientNotActive  = "client_not_active"
	denyRealmMismatch    = "realm_mismatch"
	denyNoAccessToClient = "no_access_to_client"
	denyMissingPerm      = "missing_permission"
)

type RBACService struct {
	access repository.AccessRepository
	audit  repository.AuditLogRepository
	logger *slog.Logger
}

type RBACOption func(*RBACService)

func WithRBACLogger(l *slog.Logger) RBACOption {
	return func(s *RBACService) { s.logger = l }
}

func NewRBACService(
	access repository.AccessRepository,
	audit repository.AuditLogRepository,
	opts ...RBACOption,
) *RBACService {
	s := &RBACService{
		access: access,
		audit:  audit,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type grantResult struct {
	sources    []domain.AccessSource
	policy     *domain.ClientAccessPolicy
	denyReason string
}

func (s *RBACService) resolve(ctx context.Context, userID, clientRef string) (grantResult, error) {
	if clientRef == "" {
		return grantResult{denyReason: denyClientNotFound}, nil
	}

	user, err := s.access.GetUserAccess(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return grantResult{denyReason: denyUserNotFound}, nil
	}
	if err != nil {
		return grantResult{}, fmt.Errorf("rbac: load user access: %w", err)
	}
	if user.Status != domain.UserActive {
		return grantResult{denyReason: denyUserNotActive}, nil
	}

	policy, err := s.access.GetClientAccessPolicy(ctx, clientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return grantResult{denyReason: denyClientNotFound}, nil
	}
	if err != nil {
		return grantResult{}, fmt.Errorf("rbac: load client policy: %w", err)
	}
	if policy.Status != domain.ClientAppActive {
		return grantResult{policy: policy, denyReason: denyClientNotActive}, nil
	}
	if policy.RealmID != user.RealmID {
		return grantResult{policy: policy, denyReason: denyRealmMismatch}, nil
	}

	sources := make([]domain.AccessSource, 0, len(user.Roles)+len(user.Groups))
	sources = appendAllowed(sources, user.Roles, policy.RoleIDs, user.RealmID)
	sources = appendAllowed(sources, user.Groups, policy.GroupIDs, user.RealmID)

	if len(sources) == 0 {
		return grantResult{policy: policy, denyReason: denyNoAccessToClient}, nil
	}
	return grantResult{sources: sources, policy: policy}, nil
}

func appendAllowed(dst, held []domain.AccessSource, allowedIDs []string, realmID string) []domain.AccessSource {
	for _, src := range held {
		if src.Active && src.RealmID == realmID && slices.Contains(allowedIDs, src.ID) {
			dst = append(dst, src)
		}
	}
	return dst
}

func (s *RBACService) CanAccessClient(ctx context.Context, userID, clientRef string) (bool, error) {
	res, err := s.resolve(ctx, userID, clientRef)
	if err != nil {
		return false, err
	}
	return res.denyReason == "", nil
}

func (s *RBACService) GetEffectivePermissions(ctx context.Context, userID, clientRef string) ([]*domain.Permission, error) {
	res, err := s.resolve(ctx, userID, clientRef)
	if err != nil {
		return nil, err
	}
	return effectivePermissions(res), nil
}

func (s *RBACService) GetEffectiveClientScopes(ctx context.Context, userID, clientRef string) ([]*domain.ClientScope, error) {
	res, err := s.resolve(ctx, userID, clientRef)
	if err != nil {
		return nil, err
	}
	if res.denyReason != "" {
		return []*domain.ClientScope{}, nil
	}

	realmID := res.policy.RealmID
	union := make(map[string]*domain.ClientScope)
	for _, src := range res.sources {
		for _, cs := range src.ClientScopes {
			if cs.RealmID != realmID || !slices.Contains(res.policy.ScopeIDs, cs.ID) {
				continue
			}
			union[cs.ID] = cs // only ever add: no "deny"
		}
	}

	out := make([]*domain.ClientScope, 0, len(union))
	for _, cs := range union {
		out = append(out, cs)
	}
	slices.SortFunc(out, func(a, b *domain.ClientScope) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func effectivePermissions(res grantResult) []*domain.Permission {
	if res.denyReason != "" {
		return []*domain.Permission{}
	}

	realmID := res.policy.RealmID
	union := make(map[string]*domain.Permission)
	for _, src := range res.sources {
		for _, p := range src.Permissions {
			if p.Status != domain.PermissionActive || p.RealmID != realmID {
				continue
			}
			union[p.ID] = p // only ever add: no "deny"
		}
	}

	out := make([]*domain.Permission, 0, len(union))
	for _, p := range union {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *domain.Permission) int { return strings.Compare(a.Name, b.Name) })
	return out
}

type AuthorizeInput struct {
	RealmID   string
	UserID    string
	ClientRef string // ClientApp.ID, never the public client_id
	Resource  string // e.g. "client"
	Action    string // e.g. "create"
	IPAddress string
	UserAgent string
}

func (s *RBACService) Authorize(ctx context.Context, in AuthorizeInput) error {
	res, err := s.resolve(ctx, in.UserID, in.ClientRef)
	if err != nil {
		return err
	}
	if res.denyReason != "" {
		return s.deny(ctx, in, res.denyReason)
	}

	for _, p := range effectivePermissions(res) {
		if p.Resource == in.Resource && p.Action == in.Action {
			return nil
		}
	}
	return s.deny(ctx, in, denyMissingPerm)
}

func (s *RBACService) AuthorizeClientAccess(ctx context.Context, in AuthorizeInput) error {
	res, err := s.resolve(ctx, in.UserID, in.ClientRef)
	if err != nil {
		return err
	}
	if res.denyReason != "" {
		return s.deny(ctx, in, res.denyReason)
	}
	return nil
}

func (s *RBACService) deny(ctx context.Context, in AuthorizeInput, reason string) error {
	details := map[string]interface{}{"reason": reason}
	if in.Resource != "" {
		details["resource"] = in.Resource
	}
	if in.Action != "" {
		details["action"] = in.Action
	}

	_, err := s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      in.RealmID,
		UserID:       in.UserID,
		Action:       auditActionAuthorizationDenied,
		ResourceType: "ClientApp",
		ResourceID:   in.ClientRef,
		IPAddress:    in.IPAddress,
		UserAgent:    in.UserAgent,
		Level:        domain.AuditLogWarning,
		Status:       domain.AuditLogFailure,
		Details:      details,
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "rbac: failed to write authorization denial to audit log",
			"error", err, "user_id", in.UserID, "client_ref", in.ClientRef, "reason", reason)
	}
	return ErrForbidden
}
