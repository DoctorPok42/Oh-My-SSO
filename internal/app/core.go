package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	vk "github.com/valkey-io/valkey-go"

	"sso.internal/sso/ent"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/ratelimit"
	"sso.internal/sso/internal/storage/entstore"
)

// Core is everything the binaries share: storage, caches, and the core
// services, wired exactly once.
type Core struct {
	Ent        *ent.Client
	Valkey     vk.Client
	KeyManager keymanager.KeyManager
	KMSBackend string
	PublicURL  string

	// Dispatcher sends e-mails in the background; nil when e-mail is off.
	Dispatcher *notify.Dispatcher
	// Notifier is the Dispatcher, or a no-op when e-mail is off.
	Notifier service.Notifier

	Users       repository.UserRepository
	Clients     repository.ClientRepository
	Realms      repository.RealmRepository
	Tokens      repository.TokenRepository
	SigningKeys repository.SigningKeyRepository
	Settings    repository.InstanceSettingsRepository
	Audit       repository.AuditLogRepository
	Roles       repository.RoleRepository
	Groups      repository.GroupRepository
	Scopes      repository.ClientScopeRepository
	Permissions repository.PermissionRepository
	Admin       repository.AdminRepository

	Auth          *service.AuthService
	Sessions      *service.SessionService
	RBAC          *service.RBACService
	KeyRotation   *service.KeyRotationService
	Lockout       *service.LockoutService
	MFAPolicy     *service.MFAPolicyService
	MFA           *service.MFAService
	PasswordReset *service.PasswordResetService
	Consent       *service.ConsentService
	KnownAccounts *service.KnownAccountService
	IdentityCore  *service.IdentityCoreService
	OIDCClients   *service.OIDCClientService
	SAMLClients   *service.SAMLClientService
	Timeouts      *service.TimeoutService
	RateLimiter   ratelimit.Limiter
	TrustedDevices *service.TrustedDeviceService
	// Account is the account console's service (Step 14c).
	Account *service.AccountService

	stopEnforcer func() // StartTimeoutEnforcer
}

// EmailEnabled tells whether e-mails can leave the server (SMTP, or the log
// in development). "Forgot password" and invitation e-mails need it.
func (c *Core) EmailEnabled() bool { return c.Dispatcher != nil }

func BuildCore() *Core {
	ConfigurePasswordHashing()
	c := &Core{}
	c.Ent = EntClient()
	c.KeyManager, c.KMSBackend = KeyManager()
	c.PublicURL = PublicURL()

	var err error
	c.Valkey, err = valkeycache.New(os.Getenv("VALKEY_ADDR"))
	if err != nil {
		log.Fatalf("valkey: %v", err)
	}

	client := c.Ent
	c.Users = entstore.NewUserRepository(client)
	c.Clients = entstore.NewClientRepository(client)
	c.Realms = entstore.NewRealmRepository(client)
	c.Tokens = entstore.NewTokenRepository(client)
	c.SigningKeys = entstore.NewSigningKeyRepository(client)
	c.Settings = entstore.NewInstanceSettingsRepository(client)
	c.Audit = entstore.NewAuditLogRepository(client)
	c.Roles = entstore.NewRoleRepository(client)
	c.Groups = entstore.NewGroupRepository(client)
	c.Scopes = entstore.NewClientScopeRepository(client)
	c.Permissions = entstore.NewPermissionRepository(client)
	c.Admin = entstore.NewAdminRepository(client)
	sessionRepo := entstore.NewSessionRepository(client)
	c.RateLimiter = valkeycache.NewRateLimiter(c.Valkey)

	c.Notifier = service.NopNotifier{}
	if sender := EmailSender(Templates()); sender != nil {
		c.Dispatcher = NewDispatcher(client, c.PublicURL, sender)
		c.Dispatcher.Start()
		c.Notifier = c.Dispatcher
	}

	c.Lockout = service.NewLockoutService(service.LockoutDeps{
		Users:    c.Users,
		Unknown:  valkeycache.NewLockoutStore(c.Valkey),
		Settings: c.Settings,
		Notifier: c.Notifier,
		Audit:    c.Audit,
	})

	mfaMethods := entstore.NewMfaMethodRepository(client)
	geo := GeoIP()
	loginSecurity := service.NewLoginSecurityService(service.LoginSecurityDeps{
		Sessions: sessionRepo,
		Methods:  mfaMethods,
		Audit:    c.Audit,
		Notifier: c.Notifier,
		GeoIP:    geo,
	})

	c.TrustedDevices = service.NewTrustedDeviceService(service.TrustedDeviceDeps{
		Devices:  entstore.NewTrustedDeviceRepository(client),
		Settings: c.Settings,
		Audit:    c.Audit,
	})

	c.KnownAccounts = service.NewKnownAccountService(service.KnownAccountDeps{
		Accounts: entstore.NewKnownAccountRepository(client),
		Users:    c.Users,
		Audit:    c.Audit,
		// "Forget" also ends the trust of the device.
		TrustedDevices: c.TrustedDevices,
	})

	c.Sessions = service.NewSessionService(
		sessionRepo,
		c.Settings,
		c.Tokens,
		valkeycache.NewSessionCache(c.Valkey),
		service.WithLoginObserver(loginSecurity),
		service.WithLoginObserver(c.KnownAccounts), // "Pick an account"
		service.WithAuditLog(c.Audit),
		service.WithRevocationObserver(c.TrustedDevices),
	)

	// Timeouts: checked at every sign-in and token, and the targets signed
	// out when one starts (StartTimeoutEnforcer for the scheduled ones).
	c.Timeouts = service.NewTimeoutService(service.TimeoutDeps{
		Timeouts: entstore.NewTimeoutRepository(client),
		Users:    c.Users,
		Groups:   c.Groups,
		Clients:  c.Clients,
		Tokens:   c.Tokens,
		Sessions: c.Sessions,
		Audit:    c.Audit,
	})

	c.Auth = service.NewAuthService(
		c.Users,
		entstore.NewLoginAttemptRepository(client),
		service.WithTimeoutChecker(c.Timeouts),
		service.WithLockout(c.Lockout),
	)

	c.RBAC = service.NewRBACService(entstore.NewAccessRepository(client), c.Audit)

	c.KeyRotation = service.NewKeyRotationService(
		c.SigningKeys,
		entstore.NewKeyRotationLogRepository(client),
		c.Settings,
		c.KeyManager,
		c.KMSBackend,
	)

	encrypter, ok := c.KeyManager.(keymanager.Encrypter)
	if !ok {
		log.Fatalf("keymanager: backend %q cannot encrypt (needed for TOTP secrets)", c.KMSBackend)
	}
	c.MFAPolicy = service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: c.Settings,
		Clients:  c.Clients,
		Roles:    c.Roles,
		Policies: entstore.NewMfaPolicyRepository(client),
		Access:   entstore.NewAccessRepository(client),
		Audit:    c.Audit,
	})
	c.MFA = service.NewMFAService(service.MFADeps{
		Users:         c.Users,
		Methods:       mfaMethods,
		BackupCodes:   entstore.NewMfaBackupCodeRepository(client),
		Sessions:      c.Sessions,
		Policy:        c.MFAPolicy,
		Envelope:      service.NewEnvelopeService(c.SigningKeys, encrypter, c.KMSBackend),
		Store:         valkeycache.NewMFAStore(c.Valkey),
		Limiter:       valkeycache.NewRateLimiter(c.Valkey),
		LoginAttempts: entstore.NewLoginAttemptRepository(client),
		Audit:         c.Audit,
		Realms:        c.Realms,
		Clients:       c.Clients,
		Passkeys:      Passkeys(),
		Notifier:      c.Notifier,
		Timeouts:      c.Timeouts,
		IssuerName:    os.Getenv("MFA_TOTP_ISSUER"),
		// A trusted device skips the second factor unless the sign-in looks
		// suspicious (the same analysis as the security alerts).
		TrustedDevices: c.TrustedDevices,
		Risk:           loginSecurity,
		// The second factor a user prefers on a device comes first.
		Memory: c.KnownAccounts,
	})

	passwordPolicy := service.NewPasswordPolicyService(c.Settings)
	c.PasswordReset = service.NewPasswordResetService(service.PasswordResetDeps{
		Users:    c.Users,
		Tokens:   entstore.NewPasswordResetTokenRepository(client),
		Sessions: c.Sessions,
		Policy:   passwordPolicy,
		Settings: c.Settings,
		Lockout:  c.Lockout,
		Notifier: c.Notifier,
		Audit:    c.Audit,
	})

	c.Consent = service.NewConsentService(service.ConsentDeps{
		Consents: entstore.NewConsentRepository(client),
		Clients:  c.Clients,
		Sessions: c.Sessions,
		Tokens:   c.Tokens,
		Audit:    c.Audit,
		Notifier: c.Notifier,
	})

	c.Account = service.NewAccountService(service.AccountDeps{
		Users:          c.Users,
		Admin:          c.Admin,
		Settings:       c.Settings,
		Clients:        c.Clients,
		ClientScopes:   c.Scopes,
		Tokens:         c.Tokens,
		LoginAttempts:  entstore.NewLoginAttemptRepository(client),
		Audit:          c.Audit,
		Sessions:       c.Sessions,
		Consents:       c.Consent,
		TrustedDevices: c.TrustedDevices,
		Policy:         passwordPolicy,
		Notifier:       c.Notifier,
		GeoIP:          geo,
	})

	c.IdentityCore = service.NewIdentityCore(service.IdentityCoreDeps{
		Auth:        c.Auth,
		Sessions:    c.Sessions,
		RBAC:        c.RBAC,
		Users:       c.Users,
		Clients:     c.Clients,
		Realms:      c.Realms,
		Tokens:      c.Tokens,
		SigningKeys: c.SigningKeys,
		KeyManager:  c.KeyManager,
		Timeouts:    c.Timeouts,
		MFA:         c.MFA,
		Consent:     c.Consent,
		Audit:       c.Audit,
		Accounts:    c.KnownAccounts,
	})

	c.OIDCClients = service.NewOIDCClientService(c.Clients, c.Scopes, c.Roles, c.Groups)
	c.SAMLClients = service.NewSAMLClientService(c.Clients, c.Scopes, c.Roles, c.Groups)
	return c
}

// StartTimeoutEnforcer signs out the targets of scheduled timeouts when
// they start (every service.EnforcerInterval), until Close. Both servers
// (idp and idp-admin) run it; each timeout is enforced once.
func (c *Core) StartTimeoutEnforcer() {
	if c.stopEnforcer != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Timeouts.RunEnforcer(ctx, service.EnforcerInterval)
	}()
	c.stopEnforcer = func() {
		cancel()
		<-done // a sign-out in progress finishes before the database closes
	}
}

// Close stops the timeout enforcer, lets queued e-mails leave (a few
// seconds at most), then closes Valkey and the database.
func (c *Core) Close() {
	if c.stopEnforcer != nil {
		c.stopEnforcer()
		c.stopEnforcer = nil
	}
	if c.Dispatcher != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c.Dispatcher.Close(ctx)
		cancel()
	}
	if c.Valkey != nil {
		c.Valkey.Close()
	}
	if c.Ent != nil {
		_ = c.Ent.Close()
	}
}

// NewDispatcher wires the e-mail dispatcher on the database.
func NewDispatcher(client *ent.Client, publicURL string, sender notify.EmailSender) *notify.Dispatcher {
	return notify.NewDispatcher(notify.DispatcherConfig{PublicURL: publicURL}, notify.DispatcherDeps{
		Sender:   sender,
		Users:    entstore.NewUserRepository(client),
		Realms:   entstore.NewRealmRepository(client),
		Settings: entstore.NewInstanceSettingsRepository(client),
		Audit:    entstore.NewAuditLogRepository(client),
	})
}

// CLINotifier is the notifier of command-line tools (`idp mfa reset`,
// `idp-admin recover`...): it sends right away, since the process ends
// with the command.
func CLINotifier(client *ent.Client) service.Notifier {
	sender := EmailSender(Templates())
	if sender == nil {
		return service.NopNotifier{}
	}
	return SyncNotifier{D: NewDispatcher(client, DevPublicURL(), sender)}
}

// SyncNotifier processes each event in the caller's goroutine.
type SyncNotifier struct{ D *notify.Dispatcher }

func (n SyncNotifier) Notify(ctx context.Context, e domain.NotificationEvent) {
	if err := n.D.Process(ctx, e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: e-mail not sent: %v\n", err)
	}
}

func (c *Core) AdminService() *service.AdminService {
	return service.NewAdminService(service.AdminDeps{
		Realms: c.Realms, Users: c.Users, Clients: c.Clients, Scopes: c.Scopes, Roles: c.Roles, Groups: c.Groups,
		Permissions: c.Permissions, Settings: c.Settings, Audit: c.Audit,
		Access: entstore.NewAccessRepository(c.Ent), MfaMethods: entstore.NewMfaMethodRepository(c.Ent), Admin: c.Admin,
		Sessions: c.Sessions, KeyRotation: c.KeyRotation, MFA: c.MFA, MFAPolicy: c.MFAPolicy,
		PasswordReset: c.PasswordReset, Lockout: c.Lockout, OIDCClients: c.OIDCClients, SAMLClients: c.SAMLClients,
		Notifier: c.Notifier, PublicURL: c.PublicURL, EmailEnabled: c.EmailEnabled(), KMSBackend: c.KMSBackend,
		TrustedDevices: c.TrustedDevices,
		Timeouts:       c.Timeouts,
	})
}
