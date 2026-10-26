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


const settingsUsage = `usage:
  idp settings show --realm <name>
  idp settings set  --realm <name> [--notification-email=true|false] [--suspicious-login-email=true|false]
                    [--min-password-length <n>] [--lockout-threshold <n>] [--lockout-duration <duration>]
                    [--password-reset-ttl <duration>]

--lockout-threshold 0 turns the account lockout off. Durations: 15m, 1h...
`

func runSettingsCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, settingsUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var err error
	switch args[0] {
	case "show":
		err = settingsShow(ctx, args[1:], os.Stdout)
	case "set":
		err = settingsSet(ctx, args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, settingsUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown settings command %q", args[0])}
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, settingsUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

func settingsShow(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("settings show", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	s, err := entstore.NewInstanceSettingsRepository(env.client).GetByRealmID(ctx, env.realm.ID)
	if errors.Is(err, repository.ErrNotFound) {
		fmt.Fprintln(out, "(no settings row yet, these are the defaults; `idp settings set` creates the row)")
		s = service.DefaultInstanceSettings(env.realm.ID)
		s.ManagedBy = domain.InstanceSettingsManagedByUI
	} else if err != nil {
		return err
	}
	printSettings(out, s)
	return nil
}

func printSettings(out io.Writer, s *domain.InstanceSettings) {
	fmt.Fprintf(out, "notification e-mails:        %t\n", s.NotificationEmailEnabled)
	fmt.Fprintf(out, "suspicious sign-in e-mails:  %t\n", s.SuspiciousLoginEmailEnabled)
	fmt.Fprintf(out, "min password length:         %d\n", s.MinPasswordLength)
	fmt.Fprintf(out, "lockout threshold:           %d (0 = off)\n", s.LockoutThreshold)
	fmt.Fprintf(out, "lockout duration:            %d min (doubles on repeat, max 24 h)\n", s.LockoutDurationMinutes)
	fmt.Fprintf(out, "password reset link valid:   %d min\n", s.PasswordResetTTLMinutes)
	fmt.Fprintf(out, "managed by:                  %s\n", s.ManagedBy)
}

func settingsSet(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("settings set", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	notif := fs.String("notification-email", "", "true|false: security alert e-mails")
	susp := fs.String("suspicious-login-email", "", "true|false: e-mail on unusual sign-ins")
	minLen := fs.Int("min-password-length", -1, "minimum length of new passwords (8 at least)")
	threshold := fs.Int("lockout-threshold", -1, "wrong passwords before a lock (0 = off)")
	duration := fs.Duration("lockout-duration", 0, "first lock duration, e.g. 15m")
	resetTTL := fs.Duration("password-reset-ttl", 0, "validity of reset links, e.g. 30m")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var p repository.UpdateInstanceSettingsParams
	var err error
	if p.NotificationEmailEnabled, err = optionalBool("notification-email", *notif); err != nil {
		return err
	}
	if p.SuspiciousLoginEmailEnabled, err = optionalBool("suspicious-login-email", *susp); err != nil {
		return err
	}
	if *minLen >= 0 {
		if *minLen < 8 {
			return usageError{"--min-password-length must be at least 8 (NIST SP 800-63B)"}
		}
		p.MinPasswordLength = minLen
	}
	if *threshold >= 0 {
		p.LockoutThreshold = threshold
	}
	if *duration != 0 {
		m, err := wholeMinutes("lockout-duration", *duration)
		if err != nil {
			return err
		}
		p.LockoutDurationMinutes = &m
	}
	if *resetTTL != 0 {
		m, err := wholeMinutes("password-reset-ttl", *resetTTL)
		if err != nil {
			return err
		}
		p.PasswordResetTTLMinutes = &m
	}
	actor := cliActor()
	p.UpdatedBy = &actor

	env, err := openMFAEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	repo := entstore.NewInstanceSettingsRepository(env.client)
	s, err := repo.GetByRealmID(ctx, env.realm.ID)
	if errors.Is(err, repository.ErrNotFound) {
		s, err = repo.Create(ctx, repository.CreateInstanceSettingsParams{RealmID: env.realm.ID})
	}
	if err != nil {
		return err
	}
	if s.ManagedBy == domain.InstanceSettingsManagedByConfig {
		return errors.New("these settings are managed by the configuration file (managed_by=config): change the file instead")
	}
	s, err = repo.Update(ctx, s.ID, p)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "realm %s (applies within a minute on a running server):\n", env.realm.Name)
	printSettings(out, s)
	return nil
}

func optionalBool(name, v string) (*bool, error) {
	switch v {
	case "":
		return nil, nil
	case "true":
		b := true
		return &b, nil
	case "false":
		b := false
		return &b, nil
	default:
		return nil, usageError{fmt.Sprintf("--%s: true or false", name)}
	}
}

func wholeMinutes(name string, d time.Duration) (int, error) {
	if d < time.Minute || d%time.Minute != 0 {
		return 0, usageError{fmt.Sprintf("--%s: whole minutes, at least 1m (got %s)", name, d)}
	}
	return int(d / time.Minute), nil
}
