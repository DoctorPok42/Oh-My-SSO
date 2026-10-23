package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Client scopes in the Admin API (Step 14): a named bundle of claim
// mappers ("source attribute -> claim name -> where"). A scope reaches a
// token only when the client maps it AND the user's group or role grants it.

var scopeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// Where a claim mapper may put its value.
var claimLocations = []string{"id_token", "access_token", "userinfo", "saml_attribute"}

// ClaimMapper: one line of the mapper editor.
type ClaimMapper struct {
	Source    string   `json:"source_attribute"`
	Claim     string   `json:"claim_name"`
	Locations []string `json:"token_location"`
}

// ClientScopeView: a row of the client scopes table / the drawer.
type ClientScopeView struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Protocol    string        `json:"protocol"`
	IsDefault   bool          `json:"is_default"`
	Mappers     []ClaimMapper `json:"claim_mappers"`
	Clients     int           `json:"clients"` // clients mapping it
	CreatedAt   time.Time     `json:"created_at"`
}

// ClientScopeInput: nil fields are unchanged (update) or default (create).
type ClientScopeInput struct {
	Name        *string
	Description *string
	Protocol    *string
	IsDefault   *bool
	Mappers     *[]ClaimMapper
}

func scopeView(cs *domain.ClientScope, clients int) ClientScopeView {
	v := ClientScopeView{ID: cs.ID, Name: cs.Name, Description: cs.Description, Protocol: string(cs.Protocol),
		IsDefault: cs.IsDefault, Mappers: []ClaimMapper{}, Clients: clients, CreatedAt: cs.CreatedAt}
	if v.Protocol == "" {
		v.Protocol = string(domain.ClientScopeProtocolOIDC)
	}
	for _, m := range cs.ClaimMappers {
		cm := ClaimMapper{}
		cm.Source, _ = m["source_attribute"].(string)
		cm.Claim, _ = m["claim_name"].(string)
		switch loc := m["token_location"].(type) {
		case string:
			cm.Locations = []string{loc}
		case []interface{}:
			for _, l := range loc {
				if ls, ok := l.(string); ok {
					cm.Locations = append(cm.Locations, ls)
				}
			}
		case []string:
			cm.Locations = loc
		}
		if cm.Locations == nil {
			cm.Locations = []string{}
		}
		v.Mappers = append(v.Mappers, cm)
	}
	return v
}

func (s *AdminService) ListClientScopes(ctx context.Context, realm *domain.Realm) ([]ClientScopeView, error) {
	scopes, err := s.d.Scopes.ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	usage, err := s.d.Admin.ScopeUsage(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]ClientScopeView, 0, len(scopes))
	for _, cs := range scopes {
		out = append(out, scopeView(cs, usage[cs.ID]))
	}
	slices.SortFunc(out, func(a, b ClientScopeView) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (s *AdminService) GetClientScope(ctx context.Context, realm *domain.Realm, id string) (ClientScopeView, error) {
	cs, err := s.scopeInRealm(ctx, realm.ID, id)
	if err != nil {
		return ClientScopeView{}, err
	}
	usage, err := s.d.Admin.ScopeUsage(ctx, realm.ID)
	if err != nil {
		return ClientScopeView{}, err
	}
	return scopeView(cs, usage[cs.ID]), nil
}

func checkMappers(in []ClaimMapper) ([]map[string]interface{}, error) {
	if len(in) > 50 {
		return nil, adminInvalid("claim_mappers", "at most 50 claim mappers")
	}
	out := make([]map[string]interface{}, 0, len(in))
	for i, m := range in {
		src, claim := strings.TrimSpace(m.Source), strings.TrimSpace(m.Claim)
		if src == "" || claim == "" || len(src) > 128 || len(claim) > 128 || strings.ContainsAny(claim, " \"\\") {
			return nil, adminInvalid("claim_mappers", "mapper %d: a source attribute and a claim name (no spaces) are required", i+1)
		}
		locs := []string{}
		for _, l := range m.Locations {
			if !slices.Contains(claimLocations, l) {
				return nil, adminInvalid("claim_mappers", "mapper %d: location %q is unknown (expected: %s)", i+1, l, strings.Join(claimLocations, ", "))
			}
			if !slices.Contains(locs, l) {
				locs = append(locs, l)
			}
		}
		if len(locs) == 0 {
			return nil, adminInvalid("claim_mappers", "mapper %d: pick at least one location", i+1)
		}
		out = append(out, map[string]interface{}{"source_attribute": src, "claim_name": claim, "token_location": locs})
	}
	return out, nil
}

func checkScopeProtocol(p *string) (*domain.ClientScopeProtocol, error) {
	if p == nil {
		return nil, nil
	}
	v := domain.ClientScopeProtocol(*p)
	switch v {
	case domain.ClientScopeProtocolOIDC, domain.ClientScopeProtocolSAML2, domain.ClientScopeProtocolBoth:
		return &v, nil
	}
	return nil, adminInvalid("protocol", "protocol must be oidc, saml2 or both")
}

func (s *AdminService) CreateClientScope(ctx context.Context, actor AdminActor, realm *domain.Realm, in ClientScopeInput) (ClientScopeView, error) {
	name := strOr(in.Name, "")
	if !scopeNamePattern.MatchString(name) || slices.Contains(StandardOIDCScopes, name) {
		return ClientScopeView{}, adminInvalid("name", "name: 1-64 characters among letters, digits and _ . : - (not a standard OIDC scope)")
	}
	protocol, err := checkScopeProtocol(in.Protocol)
	if err != nil {
		return ClientScopeView{}, err
	}
	if protocol == nil {
		p := domain.ClientScopeProtocolOIDC
		protocol = &p
	}
	mappers := []map[string]interface{}{}
	if in.Mappers != nil {
		if mappers, err = checkMappers(*in.Mappers); err != nil {
			return ClientScopeView{}, err
		}
	}
	if _, err := s.d.Scopes.GetByRealmAndName(ctx, realm.ID, name); err == nil {
		return ClientScopeView{}, adminConflict("name_taken", "a client scope named %q already exists", name)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return ClientScopeView{}, err
	}
	cs, err := s.d.Scopes.Create(ctx, repository.CreateClientScopeParams{RealmID: realm.ID, Name: name, Description: strOr(in.Description, "")})
	if err != nil {
		return ClientScopeView{}, fmt.Errorf("create client scope: %w", err)
	}
	isDefault := boolOr(in.IsDefault, false)
	if cs, err = s.d.Scopes.Update(ctx, cs.ID, repository.UpdateClientScopeParams{Protocol: protocol, IsDefault: &isDefault, ClaimMappers: mappers}); err != nil {
		return ClientScopeView{}, err
	}
	s.auditAdmin(ctx, actor, realm.ID, "client_scope.create", "ClientScope", cs.ID, domain.AuditLogInfo, map[string]interface{}{
		"name": name, "protocol": string(*protocol), "mappers": len(mappers),
	})
	return scopeView(cs, 0), nil
}

func (s *AdminService) UpdateClientScope(ctx context.Context, actor AdminActor, realm *domain.Realm, id string, in ClientScopeInput) (ClientScopeView, error) {
	cs, err := s.scopeInRealm(ctx, realm.ID, id)
	if err != nil {
		return ClientScopeView{}, err
	}
	upd := repository.UpdateClientScopeParams{IsDefault: in.IsDefault}
	changed := []string{}
	if in.Name != nil && strOr(in.Name, "") != cs.Name {
		name := strOr(in.Name, "")
		if !scopeNamePattern.MatchString(name) || slices.Contains(StandardOIDCScopes, name) {
			return ClientScopeView{}, adminInvalid("name", "name: 1-64 characters among letters, digits and _ . : - (not a standard OIDC scope)")
		}
		if _, err := s.d.Scopes.GetByRealmAndName(ctx, realm.ID, name); err == nil {
			return ClientScopeView{}, adminConflict("name_taken", "a client scope named %q already exists", name)
		}
		upd.Name = &name
		changed = append(changed, "name")
	}
	if in.Description != nil {
		d := strOr(in.Description, "")
		upd.Description = &d
		changed = append(changed, "description")
	}
	if upd.Protocol, err = checkScopeProtocol(in.Protocol); err != nil {
		return ClientScopeView{}, err
	}
	if upd.Protocol != nil {
		changed = append(changed, "protocol")
	}
	if in.Mappers != nil {
		if upd.ClaimMappers, err = checkMappers(*in.Mappers); err != nil {
			return ClientScopeView{}, err
		}
		changed = append(changed, "claim_mappers")
	}
	if in.IsDefault != nil {
		changed = append(changed, "is_default")
	}
	if cs, err = s.d.Scopes.Update(ctx, cs.ID, upd); err != nil {
		return ClientScopeView{}, fmt.Errorf("update client scope: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "client_scope.update", "ClientScope", cs.ID, domain.AuditLogInfo, map[string]interface{}{"changed": changed})
	return s.GetClientScope(ctx, realm, cs.ID)
}

// DeleteClientScope refuses a scope still mapped to clients: removing it
// would silently change what those applications receive.
func (s *AdminService) DeleteClientScope(ctx context.Context, actor AdminActor, realm *domain.Realm, id string) error {
	cs, err := s.scopeInRealm(ctx, realm.ID, id)
	if err != nil {
		return err
	}
	usage, err := s.d.Admin.ScopeUsage(ctx, realm.ID)
	if err != nil {
		return err
	}
	if n := usage[cs.ID]; n > 0 {
		return adminConflict("in_use", "%d client(s) use this scope: remove it from them first", n)
	}
	if err := s.d.Scopes.Delete(ctx, cs.ID); err != nil {
		return fmt.Errorf("delete client scope: %w", err)
	}
	s.auditAdmin(ctx, actor, realm.ID, "client_scope.delete", "ClientScope", cs.ID, domain.AuditLogWarning, map[string]interface{}{"name": cs.Name})
	return nil
}
