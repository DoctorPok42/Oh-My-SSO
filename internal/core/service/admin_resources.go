package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// APIResourceView: a row of the API resources table / the drawer.
type APIResourceView struct {
	ID          string    `json:"id"`
	Identifier  string    `json:"identifier"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scopes      []NameRef `json:"scopes"`
	CreatedAt   time.Time `json:"created_at"`
}

// APIResourceInput: nil fields are unchanged (update) or default (create).
type APIResourceInput struct {
	Identifier  *string // create only: it never changes
	Name        *string
	Description *string
	ScopeIDs    *[]string
}

func apiResourceView(r *domain.ApiResource) APIResourceView {
	v := APIResourceView{ID: r.ID, Identifier: r.Identifier, Name: r.Name, Description: r.Description,
		Scopes: make([]NameRef, 0, len(r.Scopes)), CreatedAt: r.CreatedAt}
	for _, cs := range r.Scopes {
		v.Scopes = append(v.Scopes, NameRef{ID: cs.ID, Name: cs.Name})
	}
	slices.SortFunc(v.Scopes, func(a, b NameRef) int { return strings.Compare(a.Name, b.Name) })
	return v
}

func (s *AdminService) ListAPIResources(ctx context.Context, realm *domain.Realm) ([]APIResourceView, error) {
	out := []APIResourceView{}
	all, err := s.d.Resources.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		out = append(out, apiResourceView(r))
	}
	slices.SortFunc(out, func(a, b APIResourceView) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out, nil
}

func (s *AdminService) GetAPIResource(ctx context.Context, realm *domain.Realm, id string) (APIResourceView, error) {
	r, err := s.apiResourceInRealm(ctx, realm.ID, id)
	if err != nil {
		return APIResourceView{}, err
	}
	return apiResourceView(r), nil
}

func (s *AdminService) apiResourceInRealm(ctx context.Context, realmID, id string) (*domain.ApiResource, error) {
	notFound := adminNotFound(i18n.M("admin.error.not_found.api_resource", "API resource not found"))
	r, err := s.d.Resources.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && r.RealmID != realmID) {
		return nil, notFound
	}
	return r, err
}

// apiResourcesUsing counts the API resources of the realm that define the
// scope.
func (s *AdminService) apiResourcesUsing(ctx context.Context, realmID, scopeID string) (int, error) {
	all, err := s.d.Resources.ListByRealm(ctx, realmID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range all {
		if slices.ContainsFunc(r.Scopes, func(cs *domain.ClientScope) bool { return cs.ID == scopeID }) {
			n++
		}
	}
	return n, nil
}

// ResourceIdentifier checks the identifier of an API resource: an absolute
// URI without fragment (RFC 8707, section 2), e.g. https://api.example.com.
func ResourceIdentifier(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || strings.Contains(raw, "#") || len(raw) > 255 ||
		strings.ContainsAny(raw, " \"\\") {
		return "", adminInvalid("identifier", i18n.M("admin.error.resource_identifier", "identifier: an absolute URI without fragment, e.g. https://api.example.com"))
	}
	return raw, nil
}

// apiResourceScopes: the scopes of an API, ids of OIDC client scopes of the
// realm, one at least (a client may ask for the API only if it may have one
// of them).
func (s *AdminService) apiResourceScopes(ctx context.Context, realmID string, ids []string) ([]string, error) {
	out, err := s.checkIDs(ctx, "scope_ids", ids, func(ctx context.Context, id string) error {
		cs, err := s.scopeInRealm(ctx, realmID, id)
		if err == nil && cs.Protocol == domain.ClientScopeProtocolSAML2 {
			return adminInvalid("scope_ids", i18n.M("admin.error.resource_scope_saml", "scope \"{name}\" is a SAML scope", "name", cs.Name))
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, adminInvalid("scope_ids", i18n.M("admin.error.resource_scopes_required", "pick at least one scope"))
	}
	return out, nil
}

func (s *AdminService) CreateAPIResource(ctx context.Context, actor AdminActor, realm *domain.Realm, in APIResourceInput) (APIResourceView, error) {
	identifier, err := ResourceIdentifier(strOr(in.Identifier, ""))
	if err != nil {
		return APIResourceView{}, err
	}
	name := strings.TrimSpace(strOr(in.Name, ""))
	if name == "" {
		name = identifier
	}
	scopeIDs, err := s.apiResourceScopes(ctx, realm.ID, listOr(in.ScopeIDs, nil))
	if err != nil {
		return APIResourceView{}, err
	}
	if _, err := s.d.Resources.GetByRealmAndIdentifier(ctx, realm.ID, identifier); err == nil {
		return APIResourceView{}, adminConflict("identifier_taken", i18n.M("admin.error.resource_identifier_taken", "an API resource with this identifier already exists"))
	} else if !errors.Is(err, repository.ErrNotFound) {
		return APIResourceView{}, err
	}
	r, err := s.d.Resources.Create(ctx, repository.CreateApiResourceParams{RealmID: realm.ID, Identifier: identifier, Name: name,
		Description: strings.TrimSpace(strOr(in.Description, "")), ScopeIDs: scopeIDs})
	if err != nil {
		return APIResourceView{}, fmt.Errorf("create API resource: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.APIResourceCreated, "ApiResource", r.ID, domain.AuditLogInfo, map[string]interface{}{
		"identifier": identifier, "name": name, "scope_ids": scopeIDs,
	})
	return apiResourceView(r), nil
}

func (s *AdminService) UpdateAPIResource(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, in APIResourceInput) (APIResourceView, error) {
	r, err := s.apiResourceInRealm(ctx, realm.ID, id)
	if err != nil {
		return APIResourceView{}, err
	}
	if in.Identifier != nil && strings.TrimSpace(*in.Identifier) != r.Identifier {
		return APIResourceView{}, adminInvalid("identifier", i18n.M("admin.error.resource_identifier_fixed", "the identifier of an API resource cannot change: APIs check it in their tokens"))
	}
	upd := repository.UpdateApiResourceParams{}
	changed := []string{}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" {
			return APIResourceView{}, adminInvalid("name", i18n.M("admin.error.name_empty", "name cannot be empty"))
		}
		upd.Name = &n
		changed = append(changed, "name")
	}
	if in.Description != nil {
		d := strings.TrimSpace(*in.Description)
		upd.Description = &d
		changed = append(changed, "description")
	}
	if in.ScopeIDs != nil {
		if upd.ScopeIDs, err = s.apiResourceScopes(ctx, realm.ID, *in.ScopeIDs); err != nil {
			return APIResourceView{}, err
		}
		changed = append(changed, "scopes")
	}
	if r, err = s.d.Resources.Update(ctx, r.ID, upd); err != nil {
		return APIResourceView{}, fmt.Errorf("update API resource: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.APIResourceUpdated, "ApiResource", r.ID, domain.AuditLogInfo, map[string]interface{}{"changed": changed})
	return apiResourceView(r), nil
}

// DeleteAPIResource: tokens already issued for it keep their audience until
// they expire; refreshing one for this API answers invalid_target.
func (s *AdminService) DeleteAPIResource(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) error {
	r, err := s.apiResourceInRealm(ctx, realm.ID, id)
	if err != nil {
		return err
	}
	if err := s.d.Resources.Delete(ctx, r.ID); err != nil {
		return fmt.Errorf("delete API resource: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, audit.APIResourceDeleted, "ApiResource", r.ID, domain.AuditLogWarning, map[string]interface{}{
		"identifier": r.Identifier, "name": r.Name,
	})
	return nil
}
