package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)


const usersUsage = `usage:
  idp users status --realm <name> --user <username|email>
  idp users unlock --realm <name> --user <username|email>
`

func runUsersCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usersUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var err error
	switch args[0] {
	case "status":
		err = usersStatus(ctx, args[1:], os.Stdout)
	case "unlock":
		err = usersUnlock(ctx, args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usersUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown users command %q", args[0])}
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, usersUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

func usersFlags(name string, args []string) (realm, user string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	r := fs.String("realm", "", "realm name (required)")
	u := fs.String("user", "", "username or email (required)")
	if err := fs.Parse(args); err != nil {
		return "", "", err
	}
	return *r, *u, nil
}

func usersStatus(ctx context.Context, args []string, out io.Writer) error {
	realmName, ident, err := usersFlags("users status", args)
	if err != nil {
		return err
	}
	env, err := openMFAEnv(ctx, realmName) // same needs: database, realm, users
	if err != nil {
		return err
	}
	defer env.close()
	user, err := env.findUser(ctx, ident)
	if err != nil {
		return err
	}
	l := user.Lockout
	now := time.Now()
	fmt.Fprintf(out, "user:              %s (%s)\n", user.Username, user.ID)
	fmt.Fprintf(out, "status:            %s\n", user.Status)
	if l.LockedAt(now) {
		fmt.Fprintf(out, "sign-in:           LOCKED until %s (%s left)\n", fmtTime(l.LockedUntil), l.LockedUntil.Sub(now).Round(time.Second))
	} else {
		fmt.Fprintln(out, "sign-in:           allowed")
	}
	fmt.Fprintf(out, "failed passwords:  %d (last: %s)\n", l.FailedCount, fmtTime(l.LastFailedAt))
	fmt.Fprintf(out, "locks in a row:    %d (last: %s)\n", l.LockCount, fmtTime(l.LastLockedAt))
	return nil
}

func usersUnlock(ctx context.Context, args []string, out io.Writer) error {
	realmName, ident, err := usersFlags("users unlock", args)
	if err != nil {
		return err
	}
	env, err := openMFAEnv(ctx, realmName)
	if err != nil {
		return err
	}
	defer env.close()
	user, err := env.findUser(ctx, ident)
	if err != nil {
		return err
	}
	lockout := service.NewLockoutService(service.LockoutDeps{
		Users:    env.users,
		Settings: entstore.NewInstanceSettingsRepository(env.client),
	})
	if err := lockout.Unlock(ctx, user); err != nil {
		return err
	}
	_, _ = entstore.NewAuditLogRepository(env.client).Create(ctx, repository.CreateAuditLogParams{
		RealmID:      user.RealmID,
		Action:       "account_unlocked",
		ResourceType: "User",
		ResourceID:   user.ID,
		Level:        domain.AuditLogWarning,
		Status:       domain.AuditLogSuccess,
		Details:      map[string]interface{}{"triggered_by": cliActor()},
	})
	fmt.Fprintf(out, "user %s: unlocked, failed sign-ins cleared\n", user.Username)
	return nil
}
