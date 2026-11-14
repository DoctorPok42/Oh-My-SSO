package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	vk "github.com/valkey-io/valkey-go"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/cache/fallback"
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
	DB         *sql.DB
	Ent        *ent.Client
	Tx         repository.Transactor // several repository calls of Ent as one transaction
	Valkey     vk.Client
	KeyManager keymanager.KeyManager
	KMSBackend string
	PublicURL  string

	// ValkeyGuard: whether Valkey answers (degraded mode otherwise); Valkey goes through it.
	ValkeyGuard *valkeycache.Guard

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
	// SignInNetworks applies the realms' IP allowlists to sign-in.
	SignInNetworks *service.SignInNetworkService
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
	// Purge deletes the data that ended (StartTimeoutEnforcer runs it).
	Purge *service.PurgeService
	// EmailVerification: "confirm your address" e-mails and their links.
	EmailVerification *service.EmailVerificationService

	stopEnforcer func() // StartTimeoutEnforcer
}

// EmailEnabled tells whether e-mails can leave the server (SMTP, or the log
// in development). "Forgot password" and invitation e-mails need it.
func (c *Core) EmailEnabled() bool { return c.Dispatcher != nil }

func BuildCore() *Core {
	ConfigurePasswordHashing()
	c := &Core{}
	c.DB = OpenDatabase()
	checkSchemaOrExit(c.DB)
	c.Ent, c.Tx = entClientOn(c.DB)
	c.KeyManager, c.KMSBackend = KeyManager()
	c.PublicURL = PublicURL()

	// Valkey must answer at startup. Later, an outage is a degraded mode:
	// its commands fail at once (Guard) and the short-lived state of
	// sign-ins goes to memory (internal/cache/fallback).
	c.Valkey, c.ValkeyGuard = valkeycache.Guarded(mustOpenValkey())

	client := c.Ent
	c.Users = entstore.NewUserRepository(client)
	c.Clients = entstore.NewClientRepository(client)
	c.Realms = entstore.NewRealmRepository(client)
	c.Tokens = entstore.NewTokenRepository(client)
	c.SigningKeys = entstore.NewSigningKeyRepository(client)
	c.Settings = entstore.NewInstanceSettingsRepository(client)
	// A bulk action of the console leaves one entry (service.BatchedAuditLog).
	c.Audit = service.BatchedAuditLog(entstore.NewAuditLogRepository(client))
	c.Roles = entstore.NewRoleRepository(client)
	c.Groups = entstore.NewGroupRepository(client)
	c.Scopes = entstore.NewClientScopeRepository(client)
	c.Permissions = entstore.NewPermissionRepository(client)
	c.Admin = entstore.NewAdminRepository(client)
	sessionRepo := entstore.NewSessionRepository(client)
	c.RateLimiter = fallback.NewLimiter(valkeycache.NewRateLimiter(c.Valkey), nil)

	encrypter, ok := c.KeyManager.(keymanager.Encrypter)
	if !ok {
		log.Fatalf("keymanager: backend %q cannot encrypt (needed for TOTP secrets and the links of queued e-mails)", c.KMSBackend)
	}
	envelope := service.NewEnvelopeService(c.SigningKeys, encrypter, c.KMSBackend)

	c.Notifier = service.NopNotifier{}
	if sender := EmailSender(Templates()); sender != nil {
		// The outbox: e-mails outlive an SMTP outage and a restart (B-12).
		c.Dispatcher = NewDispatcher(client, c.PublicURL, sender, envelope)
		c.Dispatcher.Start()
		c.Notifier = c.Dispatcher
	}

	c.EmailVerification = service.NewEmailVerificationService(service.EmailVerificationDeps{
		Tx: c.Tx, Users: c.Users, Links: entstore.NewEmailVerificationRepository(client),
		Notifier: c.Notifier, Audit: c.Audit,
	})

	c.Lockout = service.NewLockoutService(service.LockoutDeps{
		Users:   c.Users,
		Unknown: fallback.NewLockoutStore(valkeycache.NewLockoutStore(c.Valkey), nil),
		// The devices a user signed in from: a lock does not hold them.
		History:  sessionRepo,
		Settings: c.Settings,
		Notifier: c.Notifier,
		Audit:    c.Audit,
	})

	c.SignInNetworks = service.NewSignInNetworkService(c.Settings, nil)

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
	c.Purge = service.NewPurgeService(service.PurgeDeps{
		Purge:    entstore.NewPurgeRepository(client),
		Settings: c.Settings,
		Realms:   c.Admin.ListRealms,
		Audit:    c.Audit, // audit_log.purged
	})

	c.Timeouts = service.NewTimeoutService(service.TimeoutDeps{
		Timeouts: entstore.NewTimeoutRepository(client),
		Users:    c.Users,
		Groups:   c.Groups,
		Clients:  c.Clients,
		Tokens:   c.Tokens,
		Sessions: c.Sessions,
		Audit:    c.Audit,
	})

	// Failed sign-ins go to the audit log too (auth.login_failed, auth.mfa_failed).
	loginAttempts := service.AuditedLoginAttempts(entstore.NewLoginAttemptRepository(client), c.Audit, nil)

	c.Auth = service.NewAuthService(
		c.Users,
		loginAttempts,
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
		service.WithKeyRotationAudit(c.Audit),
	)

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
		Envelope:      envelope,
		Store:         fallback.NewMFAStore(valkeycache.NewMFAStore(c.Valkey), nil),
		Limiter:       c.RateLimiter,
		LoginAttempts: loginAttempts,
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
		Tx:       c.Tx,
		Users:    c.Users,
		Tokens:   entstore.NewPasswordResetTokenRepository(client),
		Sessions: c.Sessions,
		Policy:   passwordPolicy,
		Settings: c.Settings,
		Lockout:  c.Lockout,
		Notifier: c.Notifier,
		Audit:    c.Audit,
		// A link e-mailed to the address and used marks it verified (B-13).
		Verifications: entstore.NewEmailVerificationRepository(client),
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
// (idp and idp-admin) run it; each timeout is enforced once. It also starts
// the other periodic jobs: retiring expired signing keys, and purging the
// data that ended (every service.PurgeInterval, each row deleted once).
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
	retirerDone := make(chan struct{})
	go func() {
		defer close(retirerDone)
		// Expired signing keys are retired and removed from the wallet.
		c.KeyRotation.RunRetirer(ctx, c.Admin.ListRealms, 10*time.Minute)
	}()
	purgeDone := make(chan struct{})
	go func() {
		defer close(purgeDone)
		c.Purge.Run(ctx, service.PurgeInterval)
	}()
	c.stopEnforcer = func() {
		cancel()
		<-done // a sign-out in progress finishes before the database closes
		<-retirerDone
		<-purgeDone // cancelled mid-pass: the next start goes on from there
	}
}

// Close stops the timeout enforcer, lets the e-mails being sent finish (a
// few seconds at most: the others wait in the outbox for the next start),
// then closes Valkey and the database.
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

// NewDispatcher wires the e-mail dispatcher on the database and its outbox.
// sealer encrypts the links of the queued e-mails; nil: an e-mail with a
// link cannot be queued (Enqueue fails).
func NewDispatcher(client *ent.Client, publicURL string, sender notify.EmailSender, sealer notify.Sealer) *notify.Dispatcher {
	return notify.NewDispatcher(notify.DispatcherConfig{PublicURL: publicURL}, notify.DispatcherDeps{
		Sender:   sender,
		Users:    entstore.NewUserRepository(client),
		Realms:   entstore.NewRealmRepository(client),
		Settings: entstore.NewInstanceSettingsRepository(client),
		Audit:    entstore.NewAuditLogRepository(client),
		Outbox:   entstore.NewEmailOutboxRepository(client),
		Sealer:   sealer,
		Links:    NewEmailLinks(client),
		I18n:     Languages(),
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
	return SyncNotifier{D: NewDispatcher(client, DevPublicURL(), sender, nil)}
}

// SyncNotifier sends each e-mail in the caller's goroutine: it goes through
// the outbox, so that when the mail server fails the servers try again
// later. An e-mail that cannot be queued is sent directly.
type SyncNotifier struct{ D *notify.Dispatcher }

func (n SyncNotifier) Notify(ctx context.Context, e domain.NotificationEvent) {
	id, err := n.D.Enqueue(ctx, e)
	if err != nil {
		if err := n.D.Process(ctx, e); err != nil {
			fmt.Fprintf(os.Stderr, "warning: e-mail not sent: %v\n", err)
		}
		return
	}
	if id == "" {
		return // the realm does not send it
	}
	switch err := n.D.DeliverNow(ctx, id); {
	case err == nil:
	case errors.Is(err, notify.ErrPermanent):
		fmt.Fprintf(os.Stderr, "warning: e-mail not sent: %v\n", err)
	default:
		fmt.Fprintf(os.Stderr, "warning: e-mail not sent yet (%v): the server tries again for 24 h\n", err)
	}
}

func (c *Core) AdminService() *service.AdminService {
	return service.NewAdminService(service.AdminDeps{
		Tx:     c.Tx,
		Realms: c.Realms, Users: c.Users, Clients: c.Clients, Scopes: c.Scopes, Roles: c.Roles, Groups: c.Groups,
		Permissions: c.Permissions, Settings: c.Settings, Audit: c.Audit,
		Access: entstore.NewAccessRepository(c.Ent), MfaMethods: entstore.NewMfaMethodRepository(c.Ent), Admin: c.Admin,
		Sessions: c.Sessions, KeyRotation: c.KeyRotation, MFA: c.MFA, MFAPolicy: c.MFAPolicy,
		PasswordReset: c.PasswordReset, Lockout: c.Lockout, OIDCClients: c.OIDCClients, SAMLClients: c.SAMLClients,
		Notifier: c.Notifier, PublicURL: c.PublicURL, EmailEnabled: c.EmailEnabled(), KMSBackend: c.KMSBackend,
		TrustedDevices: c.TrustedDevices,
		Timeouts:       c.Timeouts,
		Languages:      Languages(),
		UserImports:    entstore.NewUserImportRepository(c.Ent),
		BulkJobs:       entstore.NewBulkJobRepository(c.Ent),
		Outbox:            entstore.NewEmailOutboxRepository(c.Ent),
		EmailVerification: c.EmailVerification,
		ConsoleURL:    os.Getenv("ADMIN_PANEL_URL"),
	})
}
