package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"sso.internal/sso/ent"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// "idp mfa" manages second factors and MFA policies from the command line
// (Step 9). Same services as the HTTP API: the admin panel (Step 14) and the
// config-as-code reconciler will call the very same functions.
//
//	idp mfa list   --realm master --user alice
//	idp mfa reset  --realm master --user alice --reason "lost phone"
//	idp mfa policy show        --realm master
//	idp mfa policy set-realm   --realm master [--required=true|false] [--step-up-max-age 10m]
//	idp mfa policy set-client  --realm master --client my-app --policy required [--methods totp,passkey]
//	idp mfa policy set-role    --realm master --role admin [--required] [--methods passkey] [--grace-days 7] [--step-up]
//	idp mfa policy delete-role --realm master --role admin

const mfaUsage = `usage:
  idp mfa list   --realm <name> --user <username|email>
  idp mfa reset  --realm <name> --user <username|email> --reason <text>
  idp mfa policy show        --realm <name>
  idp mfa policy set-realm   --realm <name> [--required=true|false] [--step-up-max-age <duration>]
  idp mfa policy set-client  --realm <name> --client <client_id|entity_id> --policy inherit|required [--methods <list>|any]
  idp mfa policy set-role    --realm <name> --role <name> [--required] [--methods <list>|any] [--grace-days <n>] [--step-up]
  idp mfa policy delete-role --realm <name> --role <name>

methods: totp, passkey, webauthn, backup_codes (comma separated)
`

func runMFACommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, mfaUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch args[0] {
	case "list":
		err = mfaList(ctx, args[1:], os.Stdout)
	case "reset":
		err = mfaReset(ctx, args[1:], os.Stdout)
	case "policy":
		err = mfaPolicy(ctx, args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, mfaUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown mfa command %q", args[0])}
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, mfaUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

// mfaEnv holds what the "mfa" subcommands need.
type mfaEnv struct {
	client  *ent.Client
	realm   *domain.Realm
	policy  *service.MFAPolicyService
	users   repository.UserRepository
	closers []func()
}

func (e *mfaEnv) close() {
	for i := len(e.closers) - 1; i >= 0; i-- {
		e.closers[i]()
	}
}

func openMFAEnv(ctx context.Context, realmName string) (*mfaEnv, error) {
	if realmName == "" {
		return nil, usageError{"--realm is required"}
	}
	if os.Getenv("DATABASE_URL") == "" {
		return nil, errors.New("DATABASE_URL is not set (hint: `make` targets load .env, or export it)")
	}
	client := buildEntClient()
	env := &mfaEnv{client: client, closers: []func(){func() { client.Close() }}}

	realm, err := entstore.NewRealmRepository(client).GetByName(ctx, realmName)
	if err != nil {
		env.close()
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("realm %q not found", realmName)
		}
		return nil, fmt.Errorf("load realm %q: %w", realmName, err)
	}
	env.realm = realm
	env.users = entstore.NewUserRepository(client)
	env.policy = service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: entstore.NewInstanceSettingsRepository(client),
		Clients:  entstore.NewClientRepository(client),
		Roles:    entstore.NewRoleRepository(client),
		Policies: entstore.NewMfaPolicyRepository(client),
		Access:   entstore.NewAccessRepository(client),
		Audit:    entstore.NewAuditLogRepository(client),
	})
	return env, nil
}

// mfaService builds the MFA service. Session revocation (reset) needs
// Valkey: the cache must learn that the sessions are revoked, otherwise
// they would stay valid there until they expire.
func (e *mfaEnv) mfaService(needSessions bool) (*service.MFAService, error) {
	deps := service.MFADeps{
		Users:       e.users,
		Methods:     entstore.NewMfaMethodRepository(e.client),
		BackupCodes: entstore.NewMfaBackupCodeRepository(e.client),
		Policy:      e.policy,
		Audit:       entstore.NewAuditLogRepository(e.client),
	}
	if needSessions {
		addr := os.Getenv("VALKEY_ADDR")
		if addr == "" {
			return nil, errors.New("VALKEY_ADDR is not set: revoking sessions needs the session cache")
		}
		vc, err := valkeycache.New(addr)
		if err != nil {
			return nil, fmt.Errorf("valkey: %w", err)
		}
		e.closers = append(e.closers, vc.Close)
		deps.Sessions = service.NewSessionService(
			entstore.NewSessionRepository(e.client),
			entstore.NewInstanceSettingsRepository(e.client),
			entstore.NewTokenRepository(e.client),
			valkeycache.NewSessionCache(vc),
		)
	}
	return service.NewMFAService(deps), nil
}

func (e *mfaEnv) findUser(ctx context.Context, identifier string) (*domain.User, error) {
	if identifier == "" {
		return nil, usageError{"--user is required"}
	}
	u, err := e.users.GetByRealmAndUsername(ctx, e.realm.ID, identifier)
	if errors.Is(err, repository.ErrNotFound) {
		u, err = e.users.GetByRealmAndEmail(ctx, e.realm.ID, identifier)
	}
	if errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("user %q not found in realm %s", identifier, e.realm.Name)
	}
	return u, err
}

func mfaList(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa list", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	userID := fs.String("user", "", "username or email (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	user, err := env.findUser(ctx, *userID)
	if err != nil {
		return err
	}
	mfa, err := env.mfaService(false)
	if err != nil {
		return err
	}
	list, err := mfa.ListFactors(ctx, user.ID)
	if err != nil {
		return err
	}
	req, err := env.policy.Requirement(ctx, user, nil)
	if err != nil && !errors.Is(err, service.ErrMFAPolicyConflict) {
		return err
	}

	fmt.Fprintf(out, "user %s (%s) - %d factor(s), backup codes %d/%d left\n", user.Username, user.ID, len(list.Methods), list.BackupCodes.Remaining, list.BackupCodes.Total)
	fmt.Fprintf(out, "policy (outside any client): required=%t methods=%s sources=%s\n\n", req.Required, methodsLabel(req.AllowedMethods), strings.Join(req.Sources, ","))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tNAME\tCREATED\tLAST USED")
	for _, m := range list.Methods {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Type, orDash(m.Name), fmtTime(m.CreatedAt), fmtTime(m.LastUsedAt))
	}
	return tw.Flush()
}

func mfaReset(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa reset", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	userID := fs.String("user", "", "username or email (required)")
	reason := fs.String("reason", "", "why (required, written to the audit log)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return usageError{"--reason is required"}
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	user, err := env.findUser(ctx, *userID)
	if err != nil {
		return err
	}
	mfa, err := env.mfaService(true)
	if err != nil {
		return err
	}
	res, err := mfa.ResetUser(ctx, user, cliActor(), *reason)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "MFA reset for %s: %d factor(s) and %d backup code(s) deleted, every session revoked.\n", user.Username, res.MethodsDeleted, res.BackupCodesDeleted)
	fmt.Fprintln(out, "The user can log in with their password and enroll new factors.")
	return nil
}

func mfaPolicy(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return usageError{"missing policy command"}
	}
	switch args[0] {
	case "show":
		return mfaPolicyShow(ctx, args[1:], out)
	case "set-realm":
		return mfaPolicySetRealm(ctx, args[1:], out)
	case "set-client":
		return mfaPolicySetClient(ctx, args[1:], out)
	case "set-role":
		return mfaPolicySetRole(ctx, args[1:], out)
	case "delete-role":
		return mfaPolicyDeleteRole(ctx, args[1:], out)
	}
	return usageError{fmt.Sprintf("unknown policy command %q", args[0])}
}

func mfaPolicyShow(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa policy show", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	o, err := env.policy.Overview(ctx, env.realm.ID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "realm %s: required globally=%t, step-up max age=%s\n\n", env.realm.Name, o.RequiredGlobally, o.StepUpMaxAge)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ROLE\tREQUIRED\tMETHODS\tGRACE DAYS\tSTEP-UP\tMANAGED BY")
	for _, r := range o.Roles {
		p := r.Policy
		fmt.Fprintf(tw, "%s\t%t\t%s\t%d\t%t\t%s\n", r.RoleName, p.Required, methodsLabel(p.AllowedMethods), p.EnrollmentGraceDays, p.StepUpForSensitiveActions, p.ManagedBy)
	}
	_ = tw.Flush()
	if len(o.Roles) == 0 {
		fmt.Fprintln(out, "(no role policy)")
	}

	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tPROTOCOL\tPOLICY\tMETHODS")
	for _, c := range o.Clients {
		fmt.Fprintf(tw, "%s (%s)\t%s\t%s\t%s\n", c.Name, clientIdentifier(c), c.Protocol, c.MFAPolicy, methodsLabel(c.MFAAllowedMethods))
	}
	_ = tw.Flush()
	if len(o.Clients) == 0 {
		fmt.Fprintln(out, "(every client inherits, any method)")
	}
	return nil
}

func mfaPolicySetRealm(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa policy set-realm", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	required := fs.String("required", "", "true or false: MFA required for every user of the realm")
	maxAge := fs.Duration("step-up-max-age", 0, "how long an MFA verification counts as recent for sensitive actions (1m to 24h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	in := service.SetRealmMFAPolicyInput{Actor: service.PolicyActor{TriggeredBy: cliActor()}}
	if set["required"] {
		b, err := strconv.ParseBool(*required)
		if err != nil {
			return usageError{"--required must be true or false"}
		}
		in.RequiredGlobally = &b
	}
	if set["step-up-max-age"] {
		in.StepUpMaxAge = maxAge
	}
	if in.RequiredGlobally == nil && in.StepUpMaxAge == nil {
		return usageError{"nothing to change: give --required and/or --step-up-max-age"}
	}

	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()
	in.RealmID = env.realm.ID

	s, err := env.policy.SetRealmPolicy(ctx, in)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "realm %s: required globally=%t, step-up max age=%dm\n", env.realm.Name, s.MFARequiredGlobally, s.MFAStepUpMaxAgeMinutes)
	return nil
}

func mfaPolicySetClient(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa policy set-client", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	clientArg := fs.String("client", "", "client_id (OIDC), entity_id (SAML) or internal id (required)")
	policy := fs.String("policy", "", "inherit or required (required)")
	methods := fs.String("methods", "any", "methods that satisfy MFA for this client, or any")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientArg == "" || *policy == "" {
		return usageError{"--client and --policy are required"}
	}
	allowed, err := service.ParseMFAMethods(*methods)
	if err != nil {
		return usageError{err.Error()}
	}

	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	client, err := findClient(ctx, entstore.NewClientRepository(env.client), env.realm.ID, *clientArg)
	if err != nil {
		return err
	}
	c, err := env.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{
		RealmID:        env.realm.ID,
		ClientRef:      client.ID,
		Policy:         domain.ClientAppMFAPolicy(*policy),
		AllowedMethods: allowed,
		Actor:          service.PolicyActor{TriggeredBy: cliActor()},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "client %s (%s): mfa policy=%s, methods=%s\n", c.Name, clientIdentifier(c), c.MFAPolicy, methodsLabel(c.MFAAllowedMethods))
	return nil
}

func mfaPolicySetRole(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa policy set-role", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	role := fs.String("role", "", "role name (required)")
	required := fs.Bool("required", false, "holders of the role must use MFA at every login")
	methods := fs.String("methods", "any", "methods that satisfy MFA for holders of the role, or any")
	grace := fs.Int("grace-days", 0, "days a holder without factor can still log in without MFA (0-365)")
	stepUp := fs.Bool("step-up", false, "sensitive actions always need a recent second factor for holders of the role")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *role == "" {
		return usageError{"--role is required"}
	}
	allowed, err := service.ParseMFAMethods(*methods)
	if err != nil {
		return usageError{err.Error()}
	}

	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	p, err := env.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{
		RealmID:                   env.realm.ID,
		RoleName:                  *role,
		Required:                  *required,
		AllowedMethods:            allowed,
		EnrollmentGraceDays:       *grace,
		StepUpForSensitiveActions: *stepUp,
		Actor:                     service.PolicyActor{TriggeredBy: cliActor()},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "role %s: required=%t methods=%s grace=%dd step-up=%t\n", *role, p.Required, methodsLabel(p.AllowedMethods), p.EnrollmentGraceDays, p.StepUpForSensitiveActions)
	return nil
}

func mfaPolicyDeleteRole(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mfa policy delete-role", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	role := fs.String("role", "", "role name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *role == "" {
		return usageError{"--role is required"}
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	if err := env.policy.DeleteRolePolicy(ctx, env.realm.ID, *role, service.PolicyActor{TriggeredBy: cliActor()}); err != nil {
		return err
	}
	fmt.Fprintf(out, "role %s: mfa policy deleted\n", *role)
	return nil
}

// findClient accepts the OIDC client_id, the SAML entity_id or the internal id.
func findClient(ctx context.Context, clients repository.ClientRepository, realmID, arg string) (*domain.ClientApp, error) {
	c, err := clients.GetByRealmAndClientID(ctx, realmID, arg)
	if errors.Is(err, repository.ErrNotFound) {
		c, err = clients.GetByRealmAndEntityID(ctx, realmID, arg)
	}
	if errors.Is(err, repository.ErrNotFound) {
		c, err = clients.GetByID(ctx, arg)
		if err == nil && c.RealmID != realmID {
			err = repository.ErrNotFound
		}
	}
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) || ent.IsNotFound(err) {
			return nil, fmt.Errorf("client %q not found in this realm", arg)
		}
		return nil, err
	}
	return c, nil
}

func clientIdentifier(c *domain.ClientApp) string {
	switch {
	case c.ClientID != "":
		return c.ClientID
	case c.EntityID != "":
		return c.EntityID
	}
	return c.ID
}

func methodsLabel(m []domain.MfaMethodType) string {
	if len(m) == 0 {
		return "any"
	}
	parts := make([]string, 0, len(m))
	for _, x := range m {
		parts = append(parts, string(x))
	}
	return strings.Join(parts, ",")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
