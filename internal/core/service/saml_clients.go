package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// SAML client management (Step 11). Same role as OIDCClientService: used by
// `idp saml clients ...` today, by the admin API (Step 14) and
// `idp config apply` later. The rules live here once.
//
// Nothing here knows XML: reading a service provider's metadata file is the
// SAML adapter's job (adapters/saml.ParseSPMetadata), which then fills a
// SAMLClientInput.

// maxEntityIDLength: SAML Core §8.3.6 caps an entity identifier at 1024
// characters.
const maxEntityIDLength = 1024

// SAMLClientInput is what an admin provides to create a SAML client.
type SAMLClientInput struct {
	RealmID string
	Name    string
	// EntityID of the service provider (its unique name, usually a URL).
	EntityID string
	// ACSURL receives the assertions (HTTP-POST binding). Only this exact
	// URL is ever used: an AuthnRequest asking for another one is refused.
	ACSURL string
	// SLOURL receives logout messages (HTTP-Redirect binding). Optional: a
	// client without it is not told when the user logs out elsewhere.
	SLOURL string
	// NameIDFormat: a URI, or a short name (persistent, transient, email,
	// unspecified). Empty: persistent.
	NameIDFormat string
	// Certificates of the service provider. With at least one, every request
	// it sends must be signed with one of them (Step 11 decision, like
	// Keycloak's "client signature required"). Without any, it can log users
	// in, but cannot send a LogoutRequest.
	Certificates []domain.ClientCertificate
	// WantResponseSigned also signs the <Response> (the <Assertion> inside
	// is always signed).
	WantResponseSigned bool
	// Pairwise gives this client its own NameID for each user (persistent
	// format), so that two clients cannot correlate their users.
	Pairwise bool
	// Scopes: names of ClientScopes (protocol saml2 or both) whose claim
	// mappers produce the SAML attributes.
	Scopes []string
	// AllowRoles / AllowGroups: whose members may use the client. Without
	// any, nobody can (deny by default, Step 6).
	AllowRoles  []string
	AllowGroups []string
	// AttributeMappings renames attributes ({"mail": "email"}).
	AttributeMappings map[string]string
	GrantedBy         string // "cli:alice"
	// RequireConsent (Step 13): users approve the service provider on a
	// consent screen before it receives any attribute. Off by default.
	RequireConsent bool
}

// SAMLClientService creates and maintains SAML clients.
type SAMLClientService struct {
	clients repository.ClientRepository
	scopes  repository.ClientScopeRepository
	// grants resolves role and group names exactly like OIDC clients do.
	grants *OIDCClientService
}

func NewSAMLClientService(clients repository.ClientRepository, scopes repository.ClientScopeRepository,
	roles repository.RoleRepository, groups repository.GroupRepository) *SAMLClientService {
	return &SAMLClientService{
		clients: clients,
		scopes:  scopes,
		grants:  NewOIDCClientService(clients, scopes, roles, groups),
	}
}

// Create validates the input, creates the client and its grants.
func (s *SAMLClientService) Create(ctx context.Context, in SAMLClientInput) (*domain.ClientApp, error) {
	cfg, err := NormalizeSAMLClient(in)
	if err != nil {
		return nil, err
	}
	if _, err := s.clients.GetByRealmAndEntityID(ctx, in.RealmID, cfg.EntityID); err == nil {
		return nil, fmt.Errorf("%w: entity_id %q already exists in this realm", ErrInvalidClientConfig, cfg.EntityID)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}

	// Resolve every name BEFORE writing anything (same rule as OIDC).
	scopeIDs, err := s.resolveSAMLScopes(ctx, in.RealmID, in.Scopes)
	if err != nil {
		return nil, err
	}
	roleIDs, err := s.grants.resolveRoles(ctx, in.RealmID, in.AllowRoles)
	if err != nil {
		return nil, err
	}
	groupIDs, err := s.grants.resolveGroups(ctx, in.RealmID, in.AllowGroups)
	if err != nil {
		return nil, err
	}

	app, err := s.clients.Create(ctx, repository.CreateClientAppParams{
		RealmID:  in.RealmID,
		Name:     cfg.Name,
		Protocol: domain.ClientAppProtocolSAML2,
	})
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	subjectType := domain.ClientAppSubjectPublic
	if in.Pairwise {
		subjectType = domain.ClientAppSubjectPairwise
	}
	assertionSigned := true
	upd := repository.UpdateClientAppParams{
		EntityID:            &cfg.EntityID,
		ACSURL:              &cfg.ACSURL,
		SLOURL:              &cfg.SLOURL,
		NameIDFormat:        &cfg.NameIDFormat,
		ClientCertificates:  certificateMaps(cfg.Certificates),
		WantAssertionSigned: &assertionSigned,
		WantResponseSigned:  &in.WantResponseSigned,
		SubjectType:         &subjectType,
		AttributeMappings:   cfg.AttributeMappings,
		RequireConsent:      &in.RequireConsent,
	}
	if app, err = s.clients.Update(ctx, app.ID, upd); err != nil {
		return nil, fmt.Errorf("configure client: %w", err)
	}
	for _, id := range scopeIDs {
		if err := s.clients.MapScope(ctx, app.ID, id); err != nil {
			return nil, fmt.Errorf("map scope: %w", err)
		}
	}
	for _, id := range roleIDs {
		if err := s.clients.GrantRole(ctx, app.ID, id, in.GrantedBy); err != nil {
			return nil, fmt.Errorf("grant role: %w", err)
		}
	}
	for _, id := range groupIDs {
		if err := s.clients.GrantGroup(ctx, app.ID, id, in.GrantedBy); err != nil {
			return nil, fmt.Errorf("grant group: %w", err)
		}
	}
	return app, nil
}

// List returns the SAML clients of a realm (deleted ones excluded).
func (s *SAMLClientService) List(ctx context.Context, realmID string) ([]*domain.ClientApp, error) {
	all, err := s.clients.ListByRealm(ctx, realmID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.ClientApp, 0, len(all))
	for _, c := range all {
		if c.Protocol == domain.ClientAppProtocolSAML2 && !c.IsDeleted() {
			out = append(out, c)
		}
	}
	return out, nil
}

// AddCertificate registers one more certificate of a service provider:
// the first half of a rotation without downtime. Give it a NotBefore when
// the service provider will start using it, and the old one a NotAfter
// (RemoveCertificate, or AddCertificate again with the dates you want).
// Adding a certificate that is already there updates its dates.
func (s *SAMLClientService) AddCertificate(ctx context.Context, realmID, entityID string, cert domain.ClientCertificate) (*domain.ClientApp, error) {
	app, err := s.lookup(ctx, realmID, entityID)
	if err != nil {
		return nil, err
	}
	norm, fp, err := NormalizeClientCertificate(cert)
	if err != nil {
		return nil, err
	}
	current, err := app.Certificates()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientConfig, err)
	}
	next := make([]domain.ClientCertificate, 0, len(current)+1)
	for _, c := range current {
		if f, err := CertificateFingerprint(c.PEM); err == nil && f == fp {
			continue // replaced below
		}
		next = append(next, c)
	}
	next = append(next, norm)
	return s.clients.Update(ctx, app.ID, repository.UpdateClientAppParams{ClientCertificates: certificateMaps(next)})
}

// RemoveCertificate removes the certificate whose SHA-256 fingerprint (hex,
// colons allowed) starts with fingerprint. At least 8 hex digits are needed,
// and the prefix must match exactly one certificate.
func (s *SAMLClientService) RemoveCertificate(ctx context.Context, realmID, entityID, fingerprint string) (*domain.ClientApp, error) {
	app, err := s.lookup(ctx, realmID, entityID)
	if err != nil {
		return nil, err
	}
	prefix := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fingerprint), ":", ""))
	if len(prefix) < 8 {
		return nil, fmt.Errorf("%w: give at least 8 hex digits of the SHA-256 fingerprint", ErrInvalidClientConfig)
	}
	current, err := app.Certificates()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientConfig, err)
	}
	next := make([]domain.ClientCertificate, 0, len(current))
	matches := 0
	for _, c := range current {
		if f, err := CertificateFingerprint(c.PEM); err == nil && strings.HasPrefix(f, prefix) {
			matches++
			continue
		}
		next = append(next, c)
	}
	switch matches {
	case 0:
		return nil, fmt.Errorf("%w: no certificate with fingerprint %s", ErrInvalidClientConfig, fingerprint)
	case 1:
	default:
		return nil, fmt.Errorf("%w: %d certificates match %s, give more digits", ErrInvalidClientConfig, matches, fingerprint)
	}
	return s.clients.Update(ctx, app.ID, repository.UpdateClientAppParams{ClientCertificates: certificateMaps(next)})
}

func (s *SAMLClientService) lookup(ctx context.Context, realmID, entityID string) (*domain.ClientApp, error) {
	app, err := s.clients.GetByRealmAndEntityID(ctx, realmID, entityID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown entity_id %q", ErrInvalidClientConfig, entityID)
	}
	if err != nil {
		return nil, err
	}
	if app.Protocol != domain.ClientAppProtocolSAML2 || app.IsDeleted() {
		return nil, fmt.Errorf("%w: unknown entity_id %q", ErrInvalidClientConfig, entityID)
	}
	return app, nil
}

func (s *SAMLClientService) resolveSAMLScopes(ctx context.Context, realmID string, names []string) ([]string, error) {
	ids := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		cs, err := s.scopes.GetByRealmAndName(ctx, realmID, n)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: unknown client scope %q", ErrInvalidClientConfig, n)
		}
		if err != nil {
			return nil, err
		}
		if cs.Protocol != domain.ClientScopeProtocolSAML2 && cs.Protocol != domain.ClientScopeProtocolBoth {
			return nil, fmt.Errorf("%w: client scope %q is for protocol %q, not saml2", ErrInvalidClientConfig, n, cs.Protocol)
		}
		if !slices.Contains(ids, cs.ID) {
			ids = append(ids, cs.ID)
		}
	}
	return ids, nil
}

// NormalizedSAMLClient is the validated form of SAMLClientInput.
type NormalizedSAMLClient struct {
	Name              string
	EntityID          string
	ACSURL            string
	SLOURL            string
	NameIDFormat      string
	Certificates      []domain.ClientCertificate
	AttributeMappings map[string]interface{}
}

// NormalizeSAMLClient checks an input without touching the database.
func NormalizeSAMLClient(in SAMLClientInput) (*NormalizedSAMLClient, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidClientConfig, fmt.Sprintf(format, a...))
	}
	out := &NormalizedSAMLClient{
		Name:     strings.TrimSpace(in.Name),
		EntityID: strings.TrimSpace(in.EntityID),
	}
	if out.EntityID == "" || len(out.EntityID) > maxEntityIDLength || strings.ContainsAny(out.EntityID, " \t\r\n") {
		return nil, bad("entity_id is required, without spaces, at most %d characters", maxEntityIDLength)
	}
	if out.Name == "" {
		out.Name = out.EntityID
	}

	var err error
	if out.ACSURL, err = validateSAMLEndpoint(in.ACSURL); err != nil {
		return nil, bad("ACS URL %q: %v", in.ACSURL, err)
	}
	if in.SLOURL != "" {
		if out.SLOURL, err = validateSAMLEndpoint(in.SLOURL); err != nil {
			return nil, bad("SLO URL %q: %v", in.SLOURL, err)
		}
	}

	if out.NameIDFormat, err = NormalizeNameIDFormat(in.NameIDFormat); err != nil {
		return nil, bad("%v", err)
	}
	if in.Pairwise && out.NameIDFormat != domain.NameIDFormatPersistent && out.NameIDFormat != domain.NameIDFormatUnspecified {
		return nil, bad("pairwise only makes sense with the persistent NameID format")
	}

	seen := map[string]bool{}
	for _, c := range in.Certificates {
		norm, fp, err := NormalizeClientCertificate(c)
		if err != nil {
			return nil, err
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out.Certificates = append(out.Certificates, norm)
	}

	out.AttributeMappings = map[string]interface{}{}
	for from, to := range in.AttributeMappings {
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if from == "" || to == "" {
			return nil, bad("attribute mapping %q -> %q: both names are required", from, to)
		}
		out.AttributeMappings[from] = to
	}
	return out, nil
}

// NormalizeNameIDFormat accepts a URI or a short name.
func NormalizeNameIDFormat(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "persistent", strings.ToLower(domain.NameIDFormatPersistent):
		return domain.NameIDFormatPersistent, nil
	case "transient", strings.ToLower(domain.NameIDFormatTransient):
		return domain.NameIDFormatTransient, nil
	case "email", "emailaddress", strings.ToLower(domain.NameIDFormatEmail):
		return domain.NameIDFormatEmail, nil
	case "unspecified", strings.ToLower(domain.NameIDFormatUnspecified):
		return domain.NameIDFormatUnspecified, nil
	default:
		return "", fmt.Errorf("NameID format %q is not supported (persistent, transient, email, unspecified)", v)
	}
}

// validateSAMLEndpoint: an absolute https URL (http only on loopback, for
// development), no fragment, no user info, no script scheme. The ACS URL is
// where the browser POSTs the assertion: a "javascript:" value would be XSS
// (CVE-2023-45683 in crewjam/saml was exactly that).
func validateSAMLEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || u.Host == "" {
		return "", errors.New("must be an absolute URL")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("must not contain a fragment")
	}
	if u.User != nil {
		return "", errors.New("must not contain user info")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", errors.New("http is only allowed for localhost / loopback addresses")
		}
	default:
		return "", fmt.Errorf("scheme %q is not allowed (https only)", u.Scheme)
	}
	return raw, nil
}

// NormalizeClientCertificate parses a certificate given as PEM or as bare
// base64 DER (the form found in SAML metadata), and returns it as PEM with
// its SHA-256 fingerprint (lowercase hex).
func NormalizeClientCertificate(c domain.ClientCertificate) (domain.ClientCertificate, string, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: certificate: %s", ErrInvalidClientConfig, fmt.Sprintf(format, a...))
	}
	cert, err := ParseCertificate(c.PEM)
	if err != nil {
		return domain.ClientCertificate{}, "", bad("%v", err)
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return domain.ClientCertificate{}, "", bad("only RSA and EC keys are supported")
	}
	if !c.NotBefore.IsZero() && !c.NotAfter.IsZero() && !c.NotBefore.Before(c.NotAfter) {
		return domain.ClientCertificate{}, "", bad("not_before must be before not_after")
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	sum := sha256.Sum256(cert.Raw)
	return domain.ClientCertificate{PEM: pemText, NotBefore: c.NotBefore, NotAfter: c.NotAfter}, hex.EncodeToString(sum[:]), nil
}

// ParseCertificate reads one X.509 certificate, PEM or base64 DER.
func ParseCertificate(text string) (*x509.Certificate, error) {
	text = strings.TrimSpace(text)
	var der []byte
	if block, _ := pem.Decode([]byte(text)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %q is not a CERTIFICATE", block.Type)
		}
		der = block.Bytes
	} else {
		compact := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, text)
		var err error
		if der, err = base64.StdEncoding.DecodeString(compact); err != nil {
			return nil, errors.New("neither PEM nor base64 DER")
		}
	}
	return x509.ParseCertificate(der)
}

// CertificateFingerprint is the SHA-256 of the DER bytes, lowercase hex.
func CertificateFingerprint(text string) (string, error) {
	cert, err := ParseCertificate(text)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func certificateMaps(certs []domain.ClientCertificate) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(certs)) // [] not null: "no certificate"
	for _, c := range certs {
		out = append(out, c.ToMap())
	}
	return out
}
