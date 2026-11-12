package httpserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// The Admin API is a thin layer over service.AdminService. These tests call
// the service itself, against PostgreSQL, through the refusals and the
// success of every operation of the console: the catalogue of clients,
// scopes, roles, groups, permissions, users, realms and settings.

func ptr[T any](v T) *T { return &v }

// wantAdminError checks that err is a refusal of the given kind and code.
func wantAdminError(t *testing.T, err error, kind service.AdminErrorKind, code string) {
	t.Helper()
	var ae *service.AdminError
	require.True(t, errors.As(err, &ae), "want an AdminError, got %v", err)
	require.Equal(t, kind, ae.Kind, "%v", ae)
	if code != "" {
		require.Equal(t, code, ae.Code, "%v", ae)
	}
	require.NotEmpty(t, ae.Message)
}

func serviceTestCert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "sp.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAdminService_Integration(t *testing.T) {
	e := setupAdminTestEnv(t)
	ctx := context.Background()
	svc := e.admin

	boot, err := svc.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "root@example.test",
		AdminConsoleURL: adminConsoleURL, Actor: "cli:test@host"})
	require.NoError(t, err)
	e.activate(t, boot.ActivationURL) // the recovery commands need an account that chose its password
	master, err := svc.RealmByName(ctx, "master")
	require.NoError(t, err)
	rootUser, err := e.users.GetByRealmAndUsername(ctx, master.ID, "root")
	require.NoError(t, err)
	root := service.AdminActor{UserID: rootUser.ID, Username: "root", RealmID: master.ID, IPAddress: "203.0.113.9", UserAgent: "tests"}

	_, err = svc.RealmByName(ctx, "nowhere")
	wantAdminError(t, err, service.AdminNotFound, "not_found")

	var demo *domain.Realm

	t.Run("realms", func(t *testing.T) {
		_, err := svc.CreateRealm(ctx, root, service.CreateRealmInput{Name: "Bad Name"})
		wantAdminError(t, err, service.AdminInvalid, "invalid_request")
		_, err = svc.CreateRealm(ctx, root, service.CreateRealmInput{Name: "toolong", DisplayName: strings.Repeat("x", 200)})
		wantAdminError(t, err, service.AdminInvalid, "invalid_request")
		_, err = svc.CreateRealm(ctx, root, service.CreateRealmInput{Name: "master"})
		wantAdminError(t, err, service.AdminConflict, "name_taken")

		res, err := svc.CreateRealm(ctx, root, service.CreateRealmInput{Name: "demo", DisplayName: "Demo Corp"})
		require.NoError(t, err)
		require.Equal(t, "Demo Corp", res.Realm.DisplayName)
		_, err = svc.CreateRealm(ctx, root, service.CreateRealmInput{Name: "demo"})
		wantAdminError(t, err, service.AdminConflict, "name_taken")

		demo, err = svc.RealmByName(ctx, "demo")
		require.NoError(t, err)

		list, err := svc.ListRealms(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(list), 2)
		view, err := svc.GetRealm(ctx, "demo")
		require.NoError(t, err)
		require.Equal(t, "Demo Corp", view.DisplayName)
		_, err = svc.GetRealm(ctx, "nowhere")
		wantAdminError(t, err, service.AdminNotFound, "")

		// Nothing to change: the realm comes back as it is.
		same, err := svc.UpdateRealm(ctx, root, "demo", service.UpdateRealmInput{})
		require.NoError(t, err)
		require.Equal(t, view.ID, same.ID)

		upd, err := svc.UpdateRealm(ctx, root, "demo", service.UpdateRealmInput{DisplayName: ptr("Demo")})
		require.NoError(t, err)
		require.Equal(t, "Demo", upd.DisplayName)
		_, err = svc.UpdateRealm(ctx, root, "demo", service.UpdateRealmInput{DisplayName: ptr(strings.Repeat("x", 200))})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateRealm(ctx, root, "demo", service.UpdateRealmInput{Status: ptr(domain.RealmStatus("weird"))})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateRealm(ctx, root, "master", service.UpdateRealmInput{Status: ptr(domain.RealmInactive)})
		wantAdminError(t, err, service.AdminRefused, "system_realm")
		_, err = svc.UpdateRealm(ctx, root, "nowhere", service.UpdateRealmInput{})
		wantAdminError(t, err, service.AdminNotFound, "")

		off, err := svc.UpdateRealm(ctx, root, "demo", service.UpdateRealmInput{Status: ptr(domain.RealmInactive)})
		require.NoError(t, err)
		require.Equal(t, domain.RealmInactive, off.Status)
		on, err := svc.UpdateRealm(ctx, root, "demo", service.UpdateRealmInput{Status: ptr(domain.RealmActive)})
		require.NoError(t, err)
		require.Equal(t, domain.RealmActive, on.Status)
	})

	t.Run("settings", func(t *testing.T) {
		before, err := svc.GetSettings(ctx, demo)
		require.NoError(t, err)
		require.Equal(t, "en", before.DefaultLocale)
		require.Equal(t, service.DefaultAuditLogRetentionDays, before.AuditLogRetentionDays, "one year until the realm changes it")
		require.NotEmpty(t, svc.Languages())

		for name, patch := range map[string]service.SettingsPatch{
			"password length":      {MinPasswordLength: ptr(3)},
			"key grace":            {KeyRotationGraceHours: ptr(0)},
			"ip entry":             {IPAllowlist: ptr([]string{"not-an-ip"})},
			"locale":               {DefaultLocale: ptr("xx-nowhere")},
			"remember idle>max":    {RememberMeIdleDays: ptr(40), RememberMeMaxDays: ptr(30)},
			"remember max<normal":  {SessionMaxHours: ptr(48), RememberMeIdleDays: ptr(1), RememberMeMaxDays: ptr(1)},
			"remember idle<normal": {SessionIdleMinutes: ptr(4320), RememberMeIdleDays: ptr(1), RememberMeMaxDays: ptr(30)},
			"idle<step-up":         {RememberMeEnabled: ptr(false), SessionIdleMinutes: ptr(2), MFAStepUpMaxAgeMinutes: nil},
			"audit retention":      {AuditLogRetentionDays: ptr(7)},
			"audit retention < 0":  {AuditLogRetentionDays: ptr(-1)},
		} {
			_, err := svc.UpdateSettings(ctx, root, demo, patch)
			require.Error(t, err, name)
			if name != "idle<step-up" {
				wantAdminError(t, err, service.AdminInvalid, "")
			}
		}
		_, err = svc.UpdateSettings(ctx, root, master, service.SettingsPatch{MFARequiredGlobally: ptr(false)})
		wantAdminError(t, err, service.AdminRefused, "system_realm")

		after, err := svc.UpdateSettings(ctx, root, demo, service.SettingsPatch{
			MinPasswordLength: ptr(14), PasswordExpiryDays: ptr(30), PasswordResetTTLMinutes: ptr(20), InviteTTLHours: ptr(48),
			SessionIdleMinutes: ptr(45), SessionMaxHours: ptr(12), RememberMeEnabled: ptr(true), RememberMeIdleDays: ptr(3),
			RememberMeMaxDays: ptr(20), LockoutThreshold: ptr(4), LockoutDurationMinutes: ptr(15),
			IPAllowlist: ptr([]string{"10.0.0.0/8", " ", "192.0.2.7"}), MFARequiredGlobally: ptr(true), MFAStepUpMaxAgeMinutes: ptr(15),
			KeyRotationGraceHours: ptr(48), NotificationEmailEnabled: ptr(false), SuspiciousLoginEmailEnabled: ptr(false),
			DefaultLocale: ptr("fr"), AuditLogRetentionDays: ptr(365),
		})
		require.NoError(t, err)
		require.Equal(t, 14, after.MinPasswordLength)
		require.Equal(t, 365, after.AuditLogRetentionDays)
		require.Equal(t, []string{"10.0.0.0/8", "192.0.2.7"}, after.IPAllowlist)
		require.Equal(t, "fr", after.DefaultLocale)
		require.True(t, after.MFARequiredGlobally)
	})

	// Client scopes, roles, groups and permissions of the demo realm.
	var scopeID, roleID, groupID, permID string

	t.Run("client scopes", func(t *testing.T) {
		for name, in := range map[string]service.ClientScopeInput{
			"standard name": {Name: ptr("profile")},
			"bad name":      {Name: ptr("white space")},
			"bad protocol":  {Name: ptr("a"), Protocol: ptr("ldap")},
			"no source":     {Name: ptr("a"), Mappers: &[]service.ClaimMapper{{Claim: "c", Locations: []string{"id_token"}}}},
			"bad location":  {Name: ptr("a"), Mappers: &[]service.ClaimMapper{{Source: "s", Claim: "c", Locations: []string{"cookie"}}}},
			"no location":   {Name: ptr("a"), Mappers: &[]service.ClaimMapper{{Source: "s", Claim: "c"}}},
			"too many":      {Name: ptr("a"), Mappers: ptr(make([]service.ClaimMapper, 51))},
		} {
			_, err := svc.CreateClientScope(ctx, root, demo, in)
			wantAdminError(t, err, service.AdminInvalid, "")
			_ = name
		}

		cs, err := svc.CreateClientScope(ctx, root, demo, service.ClientScopeInput{
			Name: ptr("department"), Description: ptr("The department"), Protocol: ptr("both"), IsDefault: ptr(true),
			Mappers: &[]service.ClaimMapper{{Source: "profile.department", Claim: "dept", Locations: []string{"id_token", "id_token", "userinfo"}}},
		})
		require.NoError(t, err)
		scopeID = cs.ID
		require.Equal(t, "both", cs.Protocol)
		require.Equal(t, []string{"id_token", "userinfo"}, cs.Mappers[0].Locations)
		_, err = svc.CreateClientScope(ctx, root, demo, service.ClientScopeInput{Name: ptr("department")})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		other, err := svc.CreateClientScope(ctx, root, demo, service.ClientScopeInput{Name: ptr("saml-only"), Protocol: ptr("saml2")})
		require.NoError(t, err)
		require.Equal(t, "saml2", other.Protocol)

		list, err := svc.ListClientScopes(ctx, demo)
		require.NoError(t, err)
		require.Len(t, list, 2)
		require.Equal(t, "department", list[0].Name, "sorted by name")
		got, err := svc.GetClientScope(ctx, demo, scopeID)
		require.NoError(t, err)
		require.Equal(t, "The department", got.Description)
		_, err = svc.GetClientScope(ctx, demo, uuid.NewString())
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.GetClientScope(ctx, master, scopeID)
		wantAdminError(t, err, service.AdminNotFound, "")

		_, err = svc.UpdateClientScope(ctx, root, demo, scopeID, service.ClientScopeInput{Name: ptr("saml-only")})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		_, err = svc.UpdateClientScope(ctx, root, demo, scopeID, service.ClientScopeInput{Name: ptr("bad name!")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClientScope(ctx, root, demo, scopeID, service.ClientScopeInput{Protocol: ptr("ldap")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClientScope(ctx, root, demo, scopeID, service.ClientScopeInput{Mappers: &[]service.ClaimMapper{{}}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClientScope(ctx, root, demo, uuid.NewString(), service.ClientScopeInput{})
		wantAdminError(t, err, service.AdminNotFound, "")

		upd, err := svc.UpdateClientScope(ctx, root, demo, scopeID, service.ClientScopeInput{
			Name: ptr("dept"), Description: ptr("Dept"), Protocol: ptr("both"), IsDefault: ptr(false),
			Mappers: &[]service.ClaimMapper{{Source: "profile.department", Claim: "dept", Locations: []string{"access_token"}}},
		})
		require.NoError(t, err)
		require.Equal(t, "dept", upd.Name)
		require.Equal(t, "both", upd.Protocol)
		require.False(t, upd.IsDefault)

		require.NoError(t, svc.DeleteClientScope(ctx, root, demo, other.ID))
		wantAdminError(t, svc.DeleteClientScope(ctx, root, demo, other.ID), service.AdminNotFound, "")
	})

	t.Run("permissions, roles and groups", func(t *testing.T) {
		_, err := svc.CreatePermission(ctx, root, demo, service.CreatePermissionInput{Resource: "Bad", Action: "x"})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreatePermission(ctx, root, master, service.CreatePermissionInput{Resource: "invoice", Action: "approve"})
		wantAdminError(t, err, service.AdminRefused, "system_realm")
		perm, err := svc.CreatePermission(ctx, root, demo, service.CreatePermissionInput{Resource: "invoice", Action: "approve", Description: "Approve"})
		require.NoError(t, err)
		permID = perm.ID
		require.Equal(t, "invoice:approve", perm.Name)
		_, err = svc.CreatePermission(ctx, root, demo, service.CreatePermissionInput{Resource: "invoice", Action: "approve"})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		perms, err := svc.ListPermissions(ctx, demo)
		require.NoError(t, err)
		require.Len(t, perms, 1)
		masterPerms, err := svc.ListPermissions(ctx, master)
		require.NoError(t, err)
		require.True(t, masterPerms[0].System)

		// Roles.
		_, err = svc.CreateRole(ctx, root, demo, service.AccessInput{})
		wantAdminError(t, err, service.AdminInvalid, "invalid_request")
		_, err = svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("!bad")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("ok"), Description: ptr(strings.Repeat("d", 600))})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("ok"), PermissionIDs: &[]string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("ok"), ClientScopeIDs: &[]string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		role, err := svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("accountant"), Description: ptr("Accounts"),
			PermissionIDs: &[]string{permID, permID}, ClientScopeIDs: &[]string{scopeID}})
		require.NoError(t, err)
		roleID = role.ID
		require.Equal(t, []string{permID}, role.PermissionIDs)
		_, err = svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("accountant")})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		second, err := svc.CreateRole(ctx, root, demo, service.AccessInput{Name: ptr("auditor")})
		require.NoError(t, err)

		_, err = svc.UpdateRole(ctx, root, demo, roleID, service.AccessInput{Name: ptr("auditor")})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		_, err = svc.UpdateRole(ctx, root, demo, uuid.NewString(), service.AccessInput{})
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.UpdateRole(ctx, root, demo, roleID, service.AccessInput{Description: ptr(strings.Repeat("d", 600))})
		wantAdminError(t, err, service.AdminInvalid, "")
		upd, err := svc.UpdateRole(ctx, root, demo, roleID, service.AccessInput{Name: ptr("accounting"), Description: ptr("Acc"),
			Active: ptr(false), PermissionIDs: &[]string{}, ClientScopeIDs: &[]string{}})
		require.NoError(t, err)
		require.Equal(t, "accounting", upd.Name)
		require.Empty(t, upd.PermissionIDs)
		upd, err = svc.UpdateRole(ctx, root, demo, roleID, service.AccessInput{Active: ptr(true), PermissionIDs: &[]string{permID}})
		require.NoError(t, err)
		require.Equal(t, []string{permID}, upd.PermissionIDs)
		_, err = svc.UpdateRole(ctx, root, demo, roleID, service.AccessInput{}) // nothing to change: no audit entry
		require.NoError(t, err)
		roles, err := svc.ListRoles(ctx, demo)
		require.NoError(t, err)
		require.Len(t, roles, 2)
		require.NoError(t, svc.DeleteRole(ctx, root, demo, second.ID))
		wantAdminError(t, svc.DeleteRole(ctx, root, demo, second.ID), service.AdminNotFound, "")

		// Groups.
		_, err = svc.CreateGroup(ctx, root, demo, service.AccessInput{})
		wantAdminError(t, err, service.AdminInvalid, "")
		group, err := svc.CreateGroup(ctx, root, demo, service.AccessInput{Name: ptr("employees"), PermissionIDs: &[]string{permID}})
		require.NoError(t, err)
		groupID = group.ID
		_, err = svc.CreateGroup(ctx, root, demo, service.AccessInput{Name: ptr("employees")})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		contractors, err := svc.CreateGroup(ctx, root, demo, service.AccessInput{Name: ptr("contractors")})
		require.NoError(t, err)
		_, err = svc.UpdateGroup(ctx, root, demo, groupID, service.AccessInput{Name: ptr("contractors")})
		wantAdminError(t, err, service.AdminConflict, "name_taken")
		_, err = svc.UpdateGroup(ctx, root, demo, uuid.NewString(), service.AccessInput{})
		wantAdminError(t, err, service.AdminNotFound, "")
		gu, err := svc.UpdateGroup(ctx, root, demo, groupID, service.AccessInput{Name: ptr("staff"), Description: ptr("Staff"),
			Active: ptr(false), PermissionIDs: &[]string{}, ClientScopeIDs: &[]string{scopeID}})
		require.NoError(t, err)
		require.Equal(t, "staff", gu.Name)
		_, err = svc.UpdateGroup(ctx, root, demo, groupID, service.AccessInput{Active: ptr(true)})
		require.NoError(t, err)
		groups, err := svc.ListGroups(ctx, demo)
		require.NoError(t, err)
		require.Len(t, groups, 2)
		members, total, err := svc.GroupMembers(ctx, demo, groupID, repository.Page{Limit: 10})
		require.NoError(t, err)
		require.Zero(t, total)
		require.Empty(t, members)
		_, _, err = svc.GroupMembers(ctx, demo, uuid.NewString(), repository.Page{Limit: 10})
		wantAdminError(t, err, service.AdminNotFound, "")
		require.NoError(t, svc.DeleteGroup(ctx, root, demo, contractors.ID))
		wantAdminError(t, svc.DeleteGroup(ctx, root, demo, contractors.ID), service.AdminNotFound, "")

		// The system groups of the master realm cannot be edited.
		masterGroups, err := svc.ListGroups(ctx, master)
		require.NoError(t, err)
		for _, g := range masterGroups {
			_, err := svc.UpdateGroup(ctx, root, master, g.ID, service.AccessInput{Description: ptr("x")})
			wantAdminError(t, err, service.AdminRefused, "managed_by_config")
			wantAdminError(t, svc.DeleteGroup(ctx, root, master, g.ID), service.AdminRefused, "managed_by_config")
		}
		wantAdminError(t, svc.DeletePermission(ctx, root, master, masterPerms[0].ID), service.AdminRefused, "managed_by_config")

		// A permission is deleted last.
		wantAdminError(t, svc.DeletePermission(ctx, root, demo, uuid.NewString()), service.AdminNotFound, "")
		wantAdminError(t, svc.DeletePermission(ctx, root, master, permID), service.AdminNotFound, "")
	})

	var oidcID, samlID string

	t.Run("clients", func(t *testing.T) {
		_, err := svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: "ldap"})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC, AllowedRoleIDs: &[]string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC, AllowedGroupIDs: &[]string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC,
			ClientScopes: &[]service.ScopeChoiceInput{{ID: uuid.NewString()}}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC, AccessTokenTTL: ptr(-1)})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC, Name: ptr("Bad"),
			RedirectURIs: &[]string{"http://payroll.example.test/cb"}})
		require.Error(t, err)

		// A scope for SAML only cannot be mapped to an OIDC client.
		samlScope, err := svc.CreateClientScope(ctx, root, demo, service.ClientScopeInput{Name: ptr("saml-attrs"), Protocol: ptr("saml2")})
		require.NoError(t, err)
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC, Name: ptr("P"),
			RedirectURIs: &[]string{"https://p.example.test/cb"}, ClientScopes: &[]service.ScopeChoiceInput{{ID: samlScope.ID}}})
		wantAdminError(t, err, service.AdminInvalid, "")

		created, err := svc.CreateClient(ctx, root, demo, service.ClientInput{
			Protocol: domain.ClientAppProtocolOIDC, Name: ptr("Payroll"),
			RedirectURIs: &[]string{"https://payroll.example.test/cb"}, PostLogoutRedirectURIs: &[]string{"https://payroll.example.test/bye"},
			StandardScopes: &[]string{"openid", "profile"}, AccessTokenTTL: ptr(600), RefreshTokenTTL: ptr(3600), IDTokenTTL: ptr(300),
			ClientScopes:   &[]service.ScopeChoiceInput{{ID: scopeID, Required: true}, {ID: scopeID}},
			AllowedRoleIDs: &[]string{roleID}, AllowedGroupIDs: &[]string{groupID}, RequireConsent: ptr(true),
			MFAPolicy: ptr("required"), MFAMethods: &[]string{"totp"}, Active: ptr(false),
		})
		require.NoError(t, err)
		oidcID = created.Client.ID
		require.NotEmpty(t, created.Secret)
		require.Equal(t, domain.ClientAppInactive, created.Client.Status)
		require.Equal(t, "required", created.Client.MFAPolicy)
		require.Len(t, created.Client.ClientScopes, 1)
		require.Len(t, created.Client.AllowedRoles, 1)
		require.Len(t, created.Client.AllowedGroups, 1)

		public, err := svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolOIDC, ClientID: ptr("spa"),
			Name: ptr("SPA"), Public: ptr(true), RedirectURIs: &[]string{"https://spa.example.test/cb"}})
		require.NoError(t, err)
		require.Empty(t, public.Secret)

		cert := serviceTestCert(t)
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolSAML2, Name: ptr("Wiki"),
			EntityID: ptr("https://wiki.example.test/saml"), ACSURL: ptr("not a url")})
		wantAdminError(t, err, service.AdminInvalid, "")
		saml, err := svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolSAML2, Name: ptr("Wiki"),
			EntityID: ptr("https://wiki.example.test/saml"), ACSURL: ptr("https://wiki.example.test/acs"),
			SLOURL: ptr("https://wiki.example.test/slo"), NameIDFormat: ptr("email"), WantResponseSigned: ptr(true),
			DefaultRelayState: ptr("/home"), Certificates: []domain.ClientCertificate{{PEM: cert}},
			ClientScopes: &[]service.ScopeChoiceInput{{ID: scopeID}},
		})
		require.NoError(t, err)
		samlID = saml.Client.ID
		require.NotNil(t, saml.Client.SAML)
		require.Len(t, saml.Client.SAML.Certificates, 1)
		_, err = svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolSAML2, Name: ptr("Dup"),
			EntityID: ptr("https://wiki.example.test/saml"), ACSURL: ptr("https://wiki.example.test/acs")})
		require.Error(t, err)

		all, err := svc.ListClients(ctx, demo, "")
		require.NoError(t, err)
		require.Len(t, all, 3)
		onlySAML, err := svc.ListClients(ctx, demo, domain.ClientAppProtocolSAML2)
		require.NoError(t, err)
		require.Len(t, onlySAML, 1)
		view, err := svc.GetClient(ctx, demo, oidcID)
		require.NoError(t, err)
		require.True(t, view.OIDC.HasSecret)
		require.Equal(t, 600, view.OIDC.AccessTokenTTL)
		_, err = svc.GetClient(ctx, demo, uuid.NewString())
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.GetClient(ctx, master, oidcID)
		wantAdminError(t, err, service.AdminNotFound, "")

		// Changes.
		_, err = svc.UpdateClient(ctx, root, demo, uuid.NewString(), service.ClientInput{})
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{IDTokenTTL: ptr(1 << 30)})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{Name: ptr("  ")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{AllowedRoleIDs: &[]string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{AllowedGroupIDs: &[]string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{ClientScopes: &[]service.ScopeChoiceInput{{ID: uuid.NewString()}}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{RedirectURIs: &[]string{"http://payroll.example.test/cb"}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{MFAPolicy: ptr("sometimes")})
		wantAdminError(t, err, service.AdminInvalid, "")

		up, err := svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{
			Name: ptr("Payroll 2"), Active: ptr(true), RedirectURIs: &[]string{"https://payroll.example.test/cb2"},
			PostLogoutRedirectURIs: &[]string{}, StandardScopes: &[]string{"openid", "email"}, RequirePKCE: ptr(true),
			AccessTokenTTL: ptr(120), RequireConsent: ptr(false), ClientScopes: &[]service.ScopeChoiceInput{},
			AllowedRoleIDs: &[]string{}, AllowedGroupIDs: &[]string{}, MFAPolicy: ptr("inherit"), MFAMethods: &[]string{},
		})
		require.NoError(t, err)
		require.Equal(t, "Payroll 2", up.Name)
		require.Equal(t, domain.ClientAppActive, up.Status)
		require.Empty(t, up.ClientScopes)
		require.Empty(t, up.AllowedRoles)
		up, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{MFAMethods: &[]string{"totp"}})
		require.NoError(t, err)
		require.Equal(t, []string{"totp"}, up.MFAMethods)
		up, err = svc.UpdateClient(ctx, root, demo, oidcID, service.ClientInput{
			ClientScopes: &[]service.ScopeChoiceInput{{ID: scopeID}}, AllowedRoleIDs: &[]string{roleID}, AllowedGroupIDs: &[]string{groupID}})
		require.NoError(t, err)
		require.Len(t, up.ClientScopes, 1)

		// A scope still used cannot be deleted.
		wantAdminError(t, svc.DeleteClientScope(ctx, root, demo, scopeID), service.AdminConflict, "in_use")

		su, err := svc.UpdateClient(ctx, root, demo, samlID, service.ClientInput{
			Name: ptr("Wiki 2"), EntityID: ptr("https://wiki2.example.test/saml"), ACSURL: ptr("https://wiki2.example.test/acs"),
			SLOURL: ptr(""), NameIDFormat: ptr("persistent"), WantResponseSigned: ptr(false), DefaultRelayState: ptr("/start"),
		})
		require.NoError(t, err)
		require.Equal(t, "https://wiki2.example.test/saml", su.SAML.EntityID)
		_, err = svc.UpdateClient(ctx, root, demo, samlID, service.ClientInput{ACSURL: ptr("ftp://nope")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateClient(ctx, root, demo, samlID, service.ClientInput{EntityID: ptr("https://wiki.example.test/saml")})
		require.NoError(t, err)

		// Another client uses the entity ID: conflict.
		other, err := svc.CreateClient(ctx, root, demo, service.ClientInput{Protocol: domain.ClientAppProtocolSAML2, Name: ptr("Other"),
			EntityID: ptr("https://other.example.test/saml"), ACSURL: ptr("https://other.example.test/acs")})
		require.NoError(t, err)
		_, err = svc.UpdateClient(ctx, root, demo, other.Client.ID, service.ClientInput{EntityID: ptr("https://wiki.example.test/saml")})
		wantAdminError(t, err, service.AdminConflict, "entity_id_taken")

		// Secrets.
		secret, err := svc.RotateClientSecret(ctx, root, demo, oidcID)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		_, err = svc.RotateClientSecret(ctx, root, demo, samlID)
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.RotateClientSecret(ctx, root, demo, uuid.NewString())
		wantAdminError(t, err, service.AdminNotFound, "")

		// Certificates (SAML only; the last one may not be removed first).
		second := serviceTestCert(t)
		withTwo, err := svc.AddClientCertificate(ctx, root, demo, samlID, domain.ClientCertificate{PEM: second,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(100 * time.Hour)})
		require.NoError(t, err)
		require.Len(t, withTwo.SAML.Certificates, 2)
		_, err = svc.AddClientCertificate(ctx, root, demo, samlID, domain.ClientCertificate{PEM: "garbage"})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.AddClientCertificate(ctx, root, demo, oidcID, domain.ClientCertificate{PEM: second})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.RemoveClientCertificate(ctx, root, demo, oidcID, "abc")
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.RemoveClientCertificate(ctx, root, demo, samlID, "00ff")
		require.Error(t, err)
		removed, err := svc.RemoveClientCertificate(ctx, root, demo, samlID, withTwo.SAML.Certificates[0].Fingerprint)
		require.NoError(t, err)
		require.Len(t, removed.SAML.Certificates, 1)

		// The console's own client belongs to the configuration.
		masterClients, err := svc.ListClients(ctx, master, "")
		require.NoError(t, err)
		require.NotEmpty(t, masterClients)
		adminClient := masterClients[0].ID
		_, err = svc.UpdateClient(ctx, root, master, adminClient, service.ClientInput{Name: ptr("x")})
		wantAdminError(t, err, service.AdminRefused, "managed_by_config")
		wantAdminError(t, svc.DeleteClient(ctx, root, master, adminClient), service.AdminRefused, "managed_by_config")
		_, err = svc.RotateClientSecret(ctx, root, master, adminClient)
		wantAdminError(t, err, service.AdminRefused, "managed_by_config")
		_, err = svc.AddClientCertificate(ctx, root, master, adminClient, domain.ClientCertificate{PEM: second})
		wantAdminError(t, err, service.AdminRefused, "managed_by_config")

		require.NoError(t, svc.DeleteClient(ctx, root, demo, other.Client.ID))
		wantAdminError(t, svc.DeleteClient(ctx, root, demo, other.Client.ID), service.AdminNotFound, "")
	})

	var bobID string

	t.Run("users", func(t *testing.T) {
		invite := func(in service.InviteUserInput) (*service.InviteResult, error) {
			return svc.InviteUser(ctx, root, demo, in)
		}
		_, err := invite(service.InviteUserInput{Email: "not an address"})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = invite(service.InviteUserInput{Email: "x@example.test", Username: "-bad"})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = invite(service.InviteUserInput{Email: "x@example.test", Profile: map[string]interface{}{"Bad": "x"}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = invite(service.InviteUserInput{Email: "x@example.test", Profile: map[string]interface{}{"nested": map[string]interface{}{}}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = invite(service.InviteUserInput{Email: "x@example.test", Profile: map[string]interface{}{"long": strings.Repeat("a", 2000)}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = invite(service.InviteUserInput{Email: "x@example.test", GroupIDs: []string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = invite(service.InviteUserInput{Email: "x@example.test", RoleIDs: []string{uuid.NewString()}})
		wantAdminError(t, err, service.AdminInvalid, "")

		res, err := invite(service.InviteUserInput{Email: "bob@example.test", Profile: map[string]interface{}{"given_name": "Bob", "age": 42.0, "vip": true},
			GroupIDs: []string{groupID}, RoleIDs: []string{roleID}, SendEmail: true})
		require.NoError(t, err)
		bobID = res.User.ID
		require.Equal(t, "bob", res.User.Username)
		require.Contains(t, res.ActivationURL, "/r/demo/auth/reset-password#token=", "e-mail is off: the link comes back")
		require.False(t, res.Emailed)
		require.Equal(t, "Bob", res.User.Name)
		require.Len(t, res.User.Groups, 1)
		require.Len(t, res.User.Roles, 1)
		require.NotEmpty(t, res.User.Effective.Permissions, "the permission comes from the group and the role")
		_, err = invite(service.InviteUserInput{Email: "other@example.test", Username: "bob"})
		wantAdminError(t, err, service.AdminConflict, "username_taken")
		_, err = invite(service.InviteUserInput{Email: "bob@example.test", Username: "robert"})
		wantAdminError(t, err, service.AdminConflict, "email_taken")
		_, err = invite(service.InviteUserInput{Email: "other@example.test", Username: "BOB"})
		wantAdminError(t, err, service.AdminConflict, "username_taken")
		_, err = invite(service.InviteUserInput{Email: "Bob@Example.Test", Username: "robert"})
		wantAdminError(t, err, service.AdminConflict, "email_taken")
		// The sign-in form takes both in one field: neither may be the other of another account.
		_, err = invite(service.InviteUserInput{Email: "other@example.test", Username: "bob@example.test"})
		wantAdminError(t, err, service.AdminConflict, "username_taken")
		carol, err := invite(service.InviteUserInput{Email: "carol@example.test", Username: "carol"})
		require.NoError(t, err)

		// A new link replaces the previous one, until the password is chosen.
		again, err := svc.ResendActivation(ctx, root, demo, bobID, false)
		require.NoError(t, err)
		require.NotEqual(t, res.ActivationURL, again.ActivationURL)
		_, err = svc.ResendActivation(ctx, root, demo, uuid.NewString(), false)
		wantAdminError(t, err, service.AdminNotFound, "")
		e.activate(t, again.ActivationURL)
		_, err = svc.ResendActivation(ctx, root, demo, bobID, false)
		wantAdminError(t, err, service.AdminRefused, "already_activated")

		got, err := svc.GetUser(ctx, demo, bobID)
		require.NoError(t, err)
		require.True(t, got.HasPassword)
		_, err = svc.GetUser(ctx, master, bobID)
		wantAdminError(t, err, service.AdminNotFound, "")
		list, total, err := svc.ListUsers(ctx, demo, repository.UserSearch{Query: "bo", Page: repository.Page{Limit: 10}})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Equal(t, "bob", list[0].Username)
		_, total, err = svc.ListUsers(ctx, demo, repository.UserSearch{GroupID: groupID, RoleID: roleID, Status: domain.UserActive, Page: repository.Page{Limit: 10}})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		members, total, err := svc.GroupMembers(ctx, demo, groupID, repository.Page{Limit: 10})
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Equal(t, "bob", members[0].Username)

		// Changes.
		_, err = svc.UpdateUser(ctx, root, demo, uuid.NewString(), service.UpdateUserInput{})
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Username: ptr("-bad")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Email: ptr("nope")})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Username: ptr("carol")})
		wantAdminError(t, err, service.AdminConflict, "username_taken")
		_, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Email: ptr("carol@example.test")})
		wantAdminError(t, err, service.AdminConflict, "email_taken")
		_, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Status: ptr(domain.UserStatus("gone"))})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Profile: map[string]interface{}{"Bad Key": 1}})
		wantAdminError(t, err, service.AdminInvalid, "")
		up, err := svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Username: ptr("robert"), Email: ptr("robert@example.test"),
			Profile: map[string]interface{}{"family_name": "Smith", "vip": nil}})
		require.NoError(t, err)
		require.Equal(t, "robert", up.Username)
		require.Equal(t, "Smith", up.Profile["family_name"])
		require.NotContains(t, up.Profile, "vip")
		up, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Status: ptr(domain.UserSuspended)})
		require.NoError(t, err)
		require.Equal(t, domain.UserSuspended, up.Status)
		up, err = svc.UpdateUser(ctx, root, demo, bobID, service.UpdateUserInput{Status: ptr(domain.UserActive)})
		require.NoError(t, err)
		require.Equal(t, domain.UserActive, up.Status)

		_, err = svc.SetUserGroups(ctx, root, demo, bobID, []string{uuid.NewString()})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.SetUserGroups(ctx, root, demo, uuid.NewString(), nil)
		wantAdminError(t, err, service.AdminNotFound, "")
		withGroups, err := svc.SetUserGroups(ctx, root, demo, bobID, nil)
		require.NoError(t, err)
		require.Empty(t, withGroups.Groups)
		_, err = svc.SetUserRoles(ctx, root, demo, bobID, []string{uuid.NewString()})
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.SetUserRoles(ctx, root, demo, uuid.NewString(), nil)
		wantAdminError(t, err, service.AdminNotFound, "")
		withRoles, err := svc.SetUserRoles(ctx, root, demo, bobID, nil)
		require.NoError(t, err)
		require.Empty(t, withRoles.Roles)

		// Factors, locks, sessions, devices.
		_, err = svc.ResetUserMFA(ctx, root, demo, bobID, "  ")
		wantAdminError(t, err, service.AdminInvalid, "")
		_, err = svc.ResetUserMFA(ctx, root, demo, uuid.NewString(), "lost phone")
		wantAdminError(t, err, service.AdminNotFound, "")
		reset, err := svc.ResetUserMFA(ctx, root, demo, bobID, "lost phone")
		require.NoError(t, err)
		require.Zero(t, reset.MethodsDeleted)
		wantAdminError(t, svc.UnlockUser(ctx, root, demo, uuid.NewString()), service.AdminNotFound, "")
		require.NoError(t, svc.UnlockUser(ctx, root, demo, bobID))
		wantAdminError(t, svc.RevokeUserSessions(ctx, root, demo, uuid.NewString()), service.AdminNotFound, "")
		require.NoError(t, svc.RevokeUserSessions(ctx, root, demo, bobID))
		require.NoError(t, svc.RevokeTrustedDevices(ctx, root, demo, bobID))
		wantAdminError(t, svc.RevokeTrustedDevices(ctx, root, demo, uuid.NewString()), service.AdminNotFound, "")
		wantAdminError(t, svc.RevokeTrustedDevice(ctx, root, demo, bobID, uuid.NewString()), service.AdminNotFound, "")
		wantAdminError(t, svc.RevokeTrustedDevice(ctx, root, demo, uuid.NewString(), uuid.NewString()), service.AdminNotFound, "")

		sessions, total, err := svc.ListSessions(ctx, demo, service.SessionFilter{Page: repository.Page{Limit: 10}})
		require.NoError(t, err)
		require.Zero(t, total)
		require.Empty(t, sessions)
		wantAdminError(t, svc.RevokeSession(ctx, root, demo, uuid.NewString()), service.AdminNotFound, "")

		wantAdminError(t, svc.DeleteUser(ctx, root, demo, uuid.NewString()), service.AdminNotFound, "")
		require.NoError(t, svc.DeleteUser(ctx, root, demo, carol.User.ID))
		_, err = svc.GetUser(ctx, demo, carol.User.ID)
		wantAdminError(t, err, service.AdminNotFound, "")
	})

	t.Run("the administrators of the master realm", func(t *testing.T) {
		alice, err := svc.InviteUser(ctx, root, master, service.InviteUserInput{Email: "alice@example.test"})
		require.NoError(t, err)
		aliceActor := service.AdminActor{UserID: alice.User.ID, Username: "alice", RealmID: master.ID}
		groups, err := svc.ListGroups(ctx, master)
		require.NoError(t, err)
		var admins string
		for _, g := range groups {
			if g.Name == service.AdminGroupName {
				admins = g.ID
			}
		}
		require.NotEmpty(t, admins)

		// root is the only active administrator.
		wantAdminError(t, svc.DeleteUser(ctx, aliceActor, master, rootUser.ID), service.AdminRefused, "last_admin")
		_, err = svc.UpdateUser(ctx, aliceActor, master, rootUser.ID, service.UpdateUserInput{Status: ptr(domain.UserInactive)})
		wantAdminError(t, err, service.AdminRefused, "last_admin")
		_, err = svc.SetUserGroups(ctx, aliceActor, master, rootUser.ID, nil)
		wantAdminError(t, err, service.AdminRefused, "last_admin")

		// Nobody locks themselves out.
		wantAdminError(t, svc.DeleteUser(ctx, root, master, rootUser.ID), service.AdminRefused, "self_change")
		_, err = svc.UpdateUser(ctx, root, master, rootUser.ID, service.UpdateUserInput{Status: ptr(domain.UserSuspended)})
		wantAdminError(t, err, service.AdminRefused, "self_change")
		_, err = svc.SetUserGroups(ctx, root, master, rootUser.ID, nil)
		wantAdminError(t, err, service.AdminRefused, "self_change")
		_, err = svc.ResetUserMFA(ctx, root, master, rootUser.ID, "test")
		wantAdminError(t, err, service.AdminRefused, "self_change")

		// A second administrator frees the first.
		_, err = svc.SetUserGroups(ctx, root, master, alice.User.ID, []string{admins})
		require.NoError(t, err)
		_, err = svc.SetUserGroups(ctx, aliceActor, master, rootUser.ID, nil)
		require.NoError(t, err)
	})

	t.Run("MFA policies", func(t *testing.T) {
		view, err := svc.MFAPolicies(ctx, demo)
		require.NoError(t, err)
		require.NotEmpty(t, view.KnownMethods)
		require.NotEmpty(t, view.Roles)

		_, err = svc.SetRealmMFA(ctx, root, master, service.RealmMFAInput{Required: ptr(false)})
		wantAdminError(t, err, service.AdminRefused, "system_realm")
		_, err = svc.SetRealmMFA(ctx, root, master, service.RealmMFAInput{TrustedDevices: ptr(true)})
		wantAdminError(t, err, service.AdminRefused, "system_realm")
		_, err = svc.SetRealmMFA(ctx, root, demo, service.RealmMFAInput{StepUpMinutes: ptr(0)})
		require.Error(t, err)
		set, err := svc.SetRealmMFA(ctx, root, demo, service.RealmMFAInput{Required: ptr(true), StepUpMinutes: ptr(20),
			TrustedDevices: ptr(true), TrustedDeviceDays: ptr(14)})
		require.NoError(t, err)
		require.True(t, set.RequiredGlobally)
		require.Equal(t, 20, set.StepUpMaxAgeMinutes)
		require.True(t, set.TrustedDevicesEnabled)

		_, err = svc.SetRoleMFA(ctx, root, demo, uuid.NewString(), service.RolePolicyInput{})
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.SetRoleMFA(ctx, root, demo, roleID, service.RolePolicyInput{Required: true, AllowedMethods: []string{"carrier-pigeon"}})
		wantAdminError(t, err, service.AdminInvalid, "")
		withRole, err := svc.SetRoleMFA(ctx, root, demo, roleID, service.RolePolicyInput{Required: true, AllowedMethods: []string{"totp"},
			EnrollmentGraceDays: 3, StepUpForSensitiveActions: true})
		require.NoError(t, err)
		configured := false
		for _, r := range withRole.Roles {
			if r.Role.ID == roleID {
				configured = r.Configured && r.Required && r.EnrollmentGraceDays == 3
			}
		}
		require.True(t, configured)
		_, err = svc.DeleteRoleMFA(ctx, root, demo, uuid.NewString())
		wantAdminError(t, err, service.AdminNotFound, "")
		_, err = svc.DeleteRoleMFA(ctx, root, demo, roleID)
		require.NoError(t, err)
		_, err = svc.DeleteRoleMFA(ctx, root, demo, roleID) // already gone: nothing to do
		require.NoError(t, err)
	})

	t.Run("audit, dashboard and keys", func(t *testing.T) {
		rows, total, err := svc.SearchAudit(ctx, demo, repository.AuditSearch{Page: repository.Page{Limit: 5}})
		require.NoError(t, err)
		require.Greater(t, total, 5)
		require.Len(t, rows, 5)
		created, _, err := svc.SearchAudit(ctx, demo, repository.AuditSearch{Action: audit.UserInvited, Page: repository.Page{Limit: 10}})
		require.NoError(t, err)
		require.NotEmpty(t, created)
		require.Equal(t, "root", created[0].Actor.Username)
		require.True(t, created[0].Actor.Admin)
		deleted, _, err := svc.SearchAudit(ctx, demo, repository.AuditSearch{Action: audit.UserDeleted, Page: repository.Page{Limit: 10}})
		require.NoError(t, err)
		require.Equal(t, "carol", deleted[0].Target.Username, "a deleted account keeps its name in the log")

		var exported []string
		n, truncated, err := svc.ExportAudit(ctx, demo, repository.AuditSearch{}, 0, func(v service.AuditView) error {
			exported = append(exported, v.ID)
			return nil
		})
		require.NoError(t, err)
		require.False(t, truncated)
		require.Equal(t, n, len(exported))
		n, truncated, err = svc.ExportAudit(ctx, demo, repository.AuditSearch{}, 3, func(service.AuditView) error { return nil })
		require.NoError(t, err)
		require.True(t, truncated)
		require.Equal(t, 3, n)
		boom := errors.New("disk full")
		_, _, err = svc.ExportAudit(ctx, demo, repository.AuditSearch{}, 0, func(service.AuditView) error { return boom })
		require.ErrorIs(t, err, boom)
		svc.RecordAuditExport(ctx, root, demo, "csv", n, truncated, map[string][]string{"action": {"user.invited"}, "format": {"csv"}, "empty": {""}})
		exportedLog, _, err := svc.SearchAudit(ctx, demo, repository.AuditSearch{Action: audit.AuditLogExported, Page: repository.Page{Limit: 10}})
		require.NoError(t, err)
		require.Len(t, exportedLog, 1)
		require.NotEmpty(t, svc.AuditActions())

		dash, err := svc.Dashboard(ctx, demo)
		require.NoError(t, err)
		require.NotEmpty(t, dash.SigningKeys)
		require.NotEmpty(t, dash.RecentActivity)
		require.Positive(t, dash.ActiveClients)
		require.EqualValues(t, -1, dash.Logins24h.SuccessRate, "nobody signed in")
		keys, err := svc.SigningKeys(ctx, demo)
		require.NoError(t, err)
		require.NotEmpty(t, keys)
	})

	t.Run("recovery commands", func(t *testing.T) {
		changed, err := svc.SyncAdminCatalogue(ctx)
		require.NoError(t, err)
		require.False(t, changed, "the catalogue is up to date")

		secret, alerted, err := svc.RecoverClientSecret(ctx, "cli:test@host")
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Positive(t, alerted)

		lifted, _, err := svc.RecoverTimeouts(ctx, "cli:test@host")
		require.NoError(t, err)
		require.Empty(t, lifted)

		_, err = svc.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "bad", AdminConsoleURL: adminConsoleURL, Actor: "cli:test@host"})
		require.Error(t, err)
		_, err = svc.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "x@example.test", AdminConsoleURL: "ftp://console", Actor: "cli:test@host"})
		require.Error(t, err)
		_, err = svc.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "x@example.test", AdminConsoleURL: "http://console.example.test", Production: true, Actor: "cli:test@host"})
		require.Error(t, err)
	})
}
