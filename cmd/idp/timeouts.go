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

	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// idp timeouts: suspend a user, a group or a client for a while, from the
// command line (same rules as the admin console). The master realm is
// read-only here: its timeouts are managed in the admin console, and
// `idp-admin recover timeouts` lifts them all when needed.

const timeoutsUsage = `usage:
  idp timeouts list   --realm <name> [--status current|past|all]
  idp timeouts create --realm <name> (--user <username|email> | --group <name> | --client <client_id|entity_id>)
                      --reason <text> [--from <time>] [--for <length> | --until <time>]
  idp timeouts update --realm <name> --id <timeout id> [--reason <text>] [--until <time>|none]
  idp timeouts lift   --realm <name> --id <timeout id>

  <length>: 30m, 2h, 7d...   <time>: 2026-11-02T18:00:00Z, 2026-11-02 18:00 (UTC), 2026-11-02 (midnight UTC)
  Without --for or --until, the timeout has no end: it lasts until lifted.
  With VALKEY_ADDR set, create signs the targets out at once; without it,
  the running server does it within 30 seconds (sign-ins are refused at once anyway).
`

func runTimeoutsCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, timeoutsUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var err error
	switch args[0] {
	case "list":
		err = timeoutsList(ctx, args[1:], os.Stdout)
	case "create":
		err = timeoutsCreate(ctx, args[1:], os.Stdout)
	case "update":
		err = timeoutsUpdate(ctx, args[1:], os.Stdout)
	case "lift":
		err = timeoutsLift(ctx, args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, timeoutsUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown timeouts command %q", args[0])}
	}

	var usageErr usageError
	var refusal *service.TimeoutRefusal
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, timeoutsUsage)
		return 2
	case errors.As(err, &refusal):
		fmt.Fprintf(os.Stderr, "refused: %s\n", refusal.Message)
		return 1
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

// timeoutsEnv: the database, the realm, and the timeout service. withSignOut
// also opens the session cache (when VALKEY_ADDR is set) so that create
// revokes sessions itself.
func openTimeoutsEnv(ctx context.Context, realmName string, withSignOut bool) (*mfaEnv, *service.TimeoutService, error) {
	env, err := openMFAEnv(ctx, realmName)
	if err != nil {
		return nil, nil, err
	}
	deps := service.TimeoutDeps{
		Timeouts: entstore.NewTimeoutRepository(env.client),
		Users:    env.users,
		Groups:   entstore.NewGroupRepository(env.client),
		Clients:  entstore.NewClientRepository(env.client),
		Audit:    entstore.NewAuditLogRepository(env.client),
	}
	if addr := os.Getenv("VALKEY_ADDR"); withSignOut && addr != "" {
		vc, err := valkeycache.New(addr)
		if err != nil {
			env.close()
			return nil, nil, fmt.Errorf("valkey: %w", err)
		}
		env.closers = append(env.closers, vc.Close)
		deps.Tokens = entstore.NewTokenRepository(env.client)
		deps.Sessions = service.NewSessionService(
			entstore.NewSessionRepository(env.client),
			entstore.NewInstanceSettingsRepository(env.client),
			deps.Tokens,
			valkeycache.NewSessionCache(vc),
		)
	}
	return env, service.NewTimeoutService(deps), nil
}

func timeoutsList(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("timeouts list", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	status := fs.String("status", "current", "current (scheduled and active), past (ended and lifted) or all")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var current *bool
	switch *status {
	case "current", "past":
		b := *status == "current"
		current = &b
	case "all":
	default:
		return usageError{"--status: current, past or all"}
	}
	env, svc, err := openTimeoutsEnv(ctx, *realmName, false)
	if err != nil {
		return err
	}
	defer env.close()

	rows, total, err := svc.List(ctx, env.realm.ID, current, repository.Page{Limit: 200})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "realm %s: %d timeout(s) (%s)\n\n", env.realm.Name, total, *status)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTARGET\tSTATUS\tSTART\tEND\tREASON\tBY")
	now := time.Now()
	for _, t := range rows {
		target := svc.Target(ctx, t)
		fmt.Fprintf(tw, "%s\t%s %s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.TargetType, target.Name, t.StatusAt(now),
			fmtTime(t.StartsAt), endLabel(t.EndsAt), oneLine(t.Reason, 40), t.CreatedBy)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if total > len(rows) {
		fmt.Fprintf(out, "\n(%d more: use the admin console)\n", total-len(rows))
	}
	return nil
}

func timeoutsCreate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("timeouts create", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	userArg := fs.String("user", "", "username or email of the user to suspend")
	groupArg := fs.String("group", "", "name of the group to suspend (every member)")
	clientArg := fs.String("client", "", "client_id (OIDC), entity_id (SAML) or internal id of the client to suspend")
	reason := fs.String("reason", "", "why (required, kept in the audit log)")
	from := fs.String("from", "", "start (default: now)")
	length := fs.String("for", "", "how long, e.g. 2h or 7d (default: no end)")
	until := fs.String("until", "", "end (default: no end)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	set := 0
	for _, v := range []string{*userArg, *groupArg, *clientArg} {
		if v != "" {
			set++
		}
	}
	if set != 1 {
		return usageError{"give exactly one of --user, --group, --client"}
	}
	if *length != "" && *until != "" {
		return usageError{"give --for or --until, not both"}
	}
	starts, err := parseCLITime("from", *from)
	if err != nil {
		return err
	}
	ends, err := parseCLITime("until", *until)
	if err != nil {
		return err
	}
	if *length != "" {
		d, err := parseLength(*length)
		if err != nil {
			return err
		}
		base := starts
		if base.IsZero() {
			base = time.Now()
		}
		ends = base.Add(d)
	}

	env, svc, err := openTimeoutsEnv(ctx, *realmName, true)
	if err != nil {
		return err
	}
	defer env.close()

	in := service.CreateTimeoutInput{Realm: env.realm, StartsAt: starts, EndsAt: ends, Reason: *reason,
		Actor: service.TimeoutActor{By: cliActor()}}
	switch {
	case *userArg != "":
		u, err := env.findUser(ctx, *userArg)
		if err != nil {
			return err
		}
		in.TargetType, in.TargetID = domain.TimeoutTargetUser, u.ID
	case *groupArg != "":
		g, err := entstore.NewGroupRepository(env.client).GetByRealmAndName(ctx, env.realm.ID, *groupArg)
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("group %q not found in realm %s", *groupArg, env.realm.Name)
		}
		if err != nil {
			return err
		}
		in.TargetType, in.TargetID = domain.TimeoutTargetGroup, g.ID
	default:
		c, err := findClient(ctx, entstore.NewClientRepository(env.client), env.realm.ID, *clientArg)
		if err != nil {
			return err
		}
		in.TargetType, in.TargetID = domain.TimeoutTargetClientApp, c.ID
	}

	c, err := svc.Create(ctx, in)
	if err != nil {
		return err
	}
	t := c.Timeout
	auditCLI(ctx, env, "timeout_created", c, map[string]interface{}{
		"starts_at": t.StartsAt.UTC().Format(time.RFC3339), "ends_at": endLabel(t.EndsAt), "reason": t.Reason})
	fmt.Fprintf(out, "timeout %s: %s %s suspended\n", t.ID, t.TargetType, c.Target.Name)
	fmt.Fprintf(out, "  from:   %s\n  until:  %s\n  reason: %s\n", fmtTime(t.StartsAt), endLabel(t.EndsAt), t.Reason)
	switch {
	case c.SignOut != nil && t.TargetType == domain.TimeoutTargetClientApp:
		fmt.Fprintf(out, "  signed out: %d token(s) of this client revoked\n", c.SignOut.Tokens)
	case c.SignOut != nil:
		fmt.Fprintf(out, "  signed out: %d session(s) of %d user(s) revoked\n", c.SignOut.Sessions, c.SignOut.Users)
	case c.SignOutPending:
		fmt.Fprintln(out, "  sign-out failed: the running server tries again within 30 seconds (sign-ins are refused already)")
	case t.InForceAt(time.Now()):
		fmt.Fprintln(out, "  sign-out: done by the running server within 30 seconds (VALKEY_ADDR not set); sign-ins are refused already")
	default:
		fmt.Fprintln(out, "  scheduled: the targets are signed out when it starts")
	}
	return nil
}

func timeoutsUpdate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("timeouts update", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	id := fs.String("id", "", "timeout id (required, see `idp timeouts list`)")
	reason := fs.String("reason", "", "new reason")
	until := fs.String("until", "", "new end, or none (no end)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return usageError{"--id is required"}
	}
	in := service.UpdateTimeoutInput{ID: *id, Actor: service.TimeoutActor{By: cliActor()}}
	if *reason != "" {
		in.Reason = reason
	}
	switch *until {
	case "":
	case "none":
		in.EndsAt = &time.Time{}
	default:
		t, err := parseCLITime("until", *until)
		if err != nil {
			return err
		}
		in.EndsAt = &t
	}
	if in.Reason == nil && in.EndsAt == nil {
		return usageError{"nothing to change: give --reason and/or --until"}
	}
	env, svc, err := openTimeoutsEnv(ctx, *realmName, false)
	if err != nil {
		return err
	}
	defer env.close()
	in.Realm = env.realm
	c, err := svc.Update(ctx, in)
	if err != nil {
		return err
	}
	if len(c.Changed) == 0 {
		fmt.Fprintf(out, "timeout %s: nothing changed\n", c.Timeout.ID)
		return nil
	}
	auditCLI(ctx, env, "timeout_updated", c, map[string]interface{}{"changed": c.Changed})
	fmt.Fprintf(out, "timeout %s (%s %s): %s changed, until %s\n", c.Timeout.ID, c.Timeout.TargetType, c.Target.Name,
		strings.Join(c.Changed, " and "), endLabel(c.Timeout.EndsAt))
	return nil
}

func timeoutsLift(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("timeouts lift", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	id := fs.String("id", "", "timeout id (required, see `idp timeouts list`)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return usageError{"--id is required"}
	}
	env, svc, err := openTimeoutsEnv(ctx, *realmName, false)
	if err != nil {
		return err
	}
	defer env.close()
	c, err := svc.Lift(ctx, env.realm, *id, service.TimeoutActor{By: cliActor()})
	if err != nil {
		return err
	}
	auditCLI(ctx, env, "timeout_lifted", c, nil)
	fmt.Fprintf(out, "timeout %s lifted: %s %s can sign in again\n", c.Timeout.ID, c.Timeout.TargetType, c.Target.Name)
	return nil
}

// auditCLI records a change made from the command line (the admin console
// writes "admin.timeout.*" entries; the sign-out writes "timeout_enforced").
func auditCLI(ctx context.Context, env *mfaEnv, action string, c *service.TimeoutChange, details map[string]interface{}) {
	d := map[string]interface{}{"triggered_by": cliActor(), "target_type": string(c.Timeout.TargetType), "target_name": c.Target.Name}
	for k, v := range details {
		d[k] = v
	}
	_, _ = entstore.NewAuditLogRepository(env.client).Create(ctx, repository.CreateAuditLogParams{
		RealmID: env.realm.ID, Action: action, ResourceType: "Timeout", ResourceID: c.Timeout.ID,
		Level: domain.AuditLogWarning, Status: domain.AuditLogSuccess, Details: d,
	})
}

// parseLength reads "90m", "36h" or "7d" (days, which time.ParseDuration
// does not know).
func parseLength(v string) (time.Duration, error) {
	bad := usageError{fmt.Sprintf("--for %q: a length like 30m, 2h or 7d", v)}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 {
			return 0, bad
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, bad
	}
	return d, nil
}

// parseCLITime reads an RFC 3339 time, "2006-01-02 15:04" (UTC) or a date
// (midnight UTC). "" is the zero time.
func parseCLITime(name, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02T15:04", time.DateOnly} {
		if t, err := time.ParseInLocation(layout, v, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, usageError{fmt.Sprintf("--%s %q: a time like 2026-11-02T18:00:00Z, 2026-11-02 18:00 or 2026-11-02", name, v)}
}

func endLabel(t time.Time) string {
	if t.IsZero() {
		return "no end (until lifted)"
	}
	return fmtTime(t)
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
