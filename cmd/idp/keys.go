package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"text/tabwriter"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)


const keysUsage = `usage:
  idp keys list     --realm <name>
  idp keys rotate   --realm <name> [--purpose jwt_signing|saml_signing] [--type RSA|EC] [--grace <duration>] [--reason <text>] [--compromised]
  idp keys activate --realm <name> [--purpose saml_signing] [--grace <duration>] [--reason <text>]
  idp keys retire   --realm <name>
`

func runKeysCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, keysUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch args[0] {
	case "list":
		err = keysList(ctx, args[1:], os.Stdout)
	case "rotate":
		err = keysRotate(ctx, args[1:], os.Stdout)
	case "activate":
		err = keysActivate(ctx, args[1:], os.Stdout)
	case "retire":
		err = keysRetire(ctx, args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, keysUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown keys command %q\n\n%s", args[0], keysUsage)
		return 2
	}

	var usageErr usageError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, keysUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// keysEnv holds what every "keys" subcommand needs.
type keysEnv struct {
	rotation *service.KeyRotationService
	realm    *domain.Realm
	backend  string
	close    func()
}

func openKeysEnv(ctx context.Context, realmName string) (*keysEnv, error) {
	if realmName == "" {
		return nil, usageError{"--realm is required"}
	}
	if os.Getenv("DATABASE_URL") == "" {
		return nil, errors.New("DATABASE_URL is not set (hint: `make` targets load .env, or export it)")
	}

	client := buildEntClient()
	km, backend := buildKeyManager()

	realm, err := entstore.NewRealmRepository(client).GetByName(ctx, realmName)
	if errors.Is(err, repository.ErrNotFound) {
		client.Close()
		return nil, fmt.Errorf("realm %q not found", realmName)
	}
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("load realm %q: %w", realmName, err)
	}

	rotation := service.NewKeyRotationService(
		entstore.NewSigningKeyRepository(client),
		entstore.NewKeyRotationLogRepository(client),
		entstore.NewInstanceSettingsRepository(client),
		km,
		backend,
	)
	return &keysEnv{rotation: rotation, realm: realm, backend: backend, close: func() { client.Close() }}, nil
}

func keysList(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keys list", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	env, err := openKeysEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	keys, err := env.rotation.List(ctx, env.realm.ID)
	if err != nil {
		return err
	}
	grace, err := env.rotation.GracePeriod(ctx, env.realm.ID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "realm %s - %d key(s) - grace period %s\n\n", env.realm.Name, len(keys), grace)
	printKeys(out, keys)
	return nil
}

func keysRotate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	purpose := fs.String("purpose", string(domain.SigningKeyPurposeJWT), "jwt_signing (OIDC) or saml_signing (SAML, two-step rotation)")
	keyType := fs.String("type", "", "type of the new key: RSA or EC (default: same as the current key, RSA if none)")
	grace := fs.Duration("grace", 0, "grace period of the old key, e.g. 48h (default: the realm's key_rotation_grace_hours)")
	reason := fs.String("reason", "", "free text written to KeyRotationLog (required with --compromised)")
	compromised := fs.Bool("compromised", false, "EMERGENCY: retire every previous key now, without grace period")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch domain.SigningKeyType(*keyType) {
	case "", domain.SigningKeyRSA, domain.SigningKeyEC:
	default:
		return usageError{fmt.Sprintf("--type must be RSA or EC, got %q", *keyType)}
	}
	switch domain.SigningKeyPurpose(*purpose) {
	case domain.SigningKeyPurposeJWT, domain.SigningKeyPurposeSAMLSigning:
	default:
		return usageError{fmt.Sprintf("--purpose must be jwt_signing or saml_signing, got %q", *purpose)}
	}

	env, err := openKeysEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	if env.backend == backendLocalDev {
		// local_dev keeps private keys in the memory of the process that
		// created them. A key created by this short-lived CLI process would
		// vanish when it exits, leaving the realm with an "active" key that
		// nobody can sign with.
		return errors.New("the local_dev KeyManager keeps private keys in process memory, so a key created by the CLI would be lost when it exits.\n" +
			"Use a real backend: KEYMANAGER_BACKEND=vault (`make dev` starts Vault)")
	}

	res, err := env.rotation.Rotate(ctx, service.RotateInput{
		RealmID:     env.realm.ID,
		Purpose:     domain.SigningKeyPurpose(*purpose),
		KeyType:     domain.SigningKeyType(*keyType),
		Grace:       *grace,
		Compromised: *compromised,
		TriggeredBy: cliActor(),
		Reason:      *reason,
	})
	if res == nil || res.NewKey == nil {
		return err
	}

	if res.NewKey.Status == domain.SigningKeyPending {
		fmt.Fprintf(out, "new PENDING key: %s (%s, %s)\n", res.NewKey.Kid, res.NewKey.KeyType, res.NewKey.Purpose)
		fmt.Fprintln(out, "It is published in the SAML metadata now, but does not sign yet.")
		fmt.Fprintln(out, "1. Give its certificate to the service providers that pinned ours (or let them reload our metadata).")
		fmt.Fprintf(out, "2. Then: idp keys activate --realm %s\n", env.realm.Name)
		printKeys(out, []*domain.SigningKey{res.NewKey})
		return err
	}
	fmt.Fprintf(out, "new active key: %s (%s)\n", res.NewKey.Kid, res.NewKey.KeyType)
	if *compromised {
		fmt.Fprintln(out, "compromised mode: previous keys retired immediately, tokens they signed no longer verify")
	} else {
		fmt.Fprintf(out, "grace period: %s\n", res.Grace)
	}
	if len(res.Rotating) > 0 {
		fmt.Fprintln(out, "\nnow rotating:")
		printKeys(out, res.Rotating)
	}
	if len(res.Retired) > 0 {
		fmt.Fprintln(out, "\nretired:")
		printKeys(out, res.Retired)
	}
	if err != nil {
		// The new key is active; something after it failed. Report it but
		// make it clear there is no need to rotate again.
		return fmt.Errorf("rotation done, but some follow-up steps failed (re-run `idp keys retire` later): %w", err)
	}
	return nil
}

func keysActivate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keys activate", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	purpose := fs.String("purpose", string(domain.SigningKeyPurposeSAMLSigning), "purpose of the pending key (saml_signing)")
	grace := fs.Duration("grace", 0, "grace period of the previous key, e.g. 24h (default: the realm's key_rotation_grace_hours)")
	reason := fs.String("reason", "", "free text written to KeyRotationLog")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openKeysEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	res, err := env.rotation.Activate(ctx, service.ActivateInput{
		RealmID:     env.realm.ID,
		Purpose:     domain.SigningKeyPurpose(*purpose),
		Grace:       *grace,
		TriggeredBy: cliActor(),
		Reason:      *reason,
	})
	if res == nil || res.NewKey == nil {
		return err
	}
	fmt.Fprintf(out, "key %s now signs (%s), grace period of the previous key: %s\n", res.NewKey.Kid, res.NewKey.Purpose, res.Grace)
	if len(res.Rotating) > 0 {
		fmt.Fprintln(out, "\nnow rotating:")
		printKeys(out, res.Rotating)
	}
	if err != nil {
		return fmt.Errorf("activation done, but some follow-up steps failed: %w", err)
	}
	return nil
}

func keysRetire(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keys retire", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	env, err := openKeysEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.close()

	retired, err := env.rotation.RetireExpired(ctx, env.realm.ID, cliActor())
	if len(retired) == 0 && err == nil {
		fmt.Fprintln(out, "nothing to retire: every rotating key is still inside its grace period")
		return nil
	}
	if len(retired) > 0 {
		fmt.Fprintln(out, "retired:")
		printKeys(out, retired)
	}
	return err
}

func printKeys(out io.Writer, keys []*domain.SigningKey) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KID\tTYPE\tPURPOSE\tSTATUS\tBACKEND\tCREATED\tRETIRE AFTER\tRETIRED AT")
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			k.Kid, k.KeyType, k.Purpose, k.Status, k.KMSBackend,
			fmtTime(k.CreatedAt), fmtTime(k.RetireAfter), fmtTime(k.RetiredAt))
	}
	_ = tw.Flush()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format(time.DateTime)
}

// cliActor is written to KeyRotationLog.triggered_by.
func cliActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}
