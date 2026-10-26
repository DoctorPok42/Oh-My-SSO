package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"sso.internal/sso/ent"
	samladapter "sso.internal/sso/internal/adapters/saml"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)


const samlUsage = `usage:
  idp saml clients list        --realm <name>
  idp saml clients create      --realm <name> (--metadata-file <file> | --metadata-url <url> | --entity-id <id> --acs-url <url>)
                               [--slo-url <url>] [--cert-file <pem>...] [--name <text>]
                               [--name-id-format persistent|transient|email|unspecified] [--pairwise]
                               [--want-response-signed] [--scope <a,b>] [--rename from=to,...]
                               [--allow-role <name>] [--allow-group <name>] [--require-consent]
  idp saml clients add-cert    --realm <name> --entity-id <id> --cert-file <pem> [--not-before <RFC3339>] [--not-after <RFC3339>]
  idp saml clients remove-cert --realm <name> --entity-id <id> --fingerprint <sha256 hex prefix>
`

func runSAMLCommand(args []string) int {
	if len(args) < 2 || args[0] != "clients" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			fmt.Fprint(os.Stdout, samlUsage)
			return 0
		}
		fmt.Fprint(os.Stderr, samlUsage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch args[1] {
	case "list":
		err = samlClientsList(ctx, args[2:], os.Stdout)
	case "create":
		err = samlClientsCreate(ctx, args[2:], os.Stdout)
	case "add-cert":
		err = samlClientsAddCert(ctx, args[2:], os.Stdout)
	case "remove-cert":
		err = samlClientsRemoveCert(ctx, args[2:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, samlUsage)
		return 0
	default:
		err = usageError{fmt.Sprintf("unknown saml clients command %q", args[1])}
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, samlUsage)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
}

type samlEnv struct {
	client  *ent.Client
	realm   *domain.Realm
	clients *service.SAMLClientService
}

func openSAMLEnv(ctx context.Context, realmName string) (*samlEnv, error) {
	if realmName == "" {
		return nil, usageError{"--realm is required"}
	}
	if os.Getenv("DATABASE_URL") == "" {
		return nil, errors.New("DATABASE_URL is not set (hint: `make` targets load .env, or export it)")
	}
	client := buildEntClient()
	realm, err := entstore.NewRealmRepository(client).GetByName(ctx, realmName)
	if errors.Is(err, repository.ErrNotFound) {
		client.Close()
		return nil, fmt.Errorf("realm %q not found", realmName)
	}
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("load realm %q: %w", realmName, err)
	}
	svc := service.NewSAMLClientService(
		entstore.NewClientRepository(client),
		entstore.NewClientScopeRepository(client),
		entstore.NewRoleRepository(client),
		entstore.NewGroupRepository(client),
	)
	return &samlEnv{client: client, realm: realm, clients: svc}, nil
}

func samlClientsList(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("saml clients list", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env, err := openSAMLEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()

	list, err := env.clients.List(ctx, env.realm.ID)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ENTITY ID\tNAME\tSTATUS\tNAMEID\tSLO\tCONSENT\tCERTIFICATES (sha256, window)")
	for _, c := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.EntityID, c.Name, c.Status,
			shortNameIDFormat(c.NameIDFormat), yesNo(c.SLOURL != ""), consentLabel(c.RequireConsent), describeCertificates(c))
	}
	return tw.Flush()
}

func samlClientsCreate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("saml clients create", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	metadataFile := fs.String("metadata-file", "", "SAML metadata XML of the service provider")
	metadataURL := fs.String("metadata-url", "", "URL of the service provider's metadata (fetched once)")
	name := fs.String("name", "", "display name (default: the entity ID)")
	entityID := fs.String("entity-id", "", "entity ID of the service provider (default: from the metadata)")
	acsURL := fs.String("acs-url", "", "Assertion Consumer Service URL, HTTP-POST (default: from the metadata)")
	sloURL := fs.String("slo-url", "", "Single Logout URL, HTTP-Redirect (default: from the metadata)")
	nameIDFormat := fs.String("name-id-format", "", "persistent (default), transient, email or unspecified")
	pairwise := fs.Bool("pairwise", false, "give this provider its own persistent NameID per user")
	wantResponseSigned := fs.Bool("want-response-signed", false, "also sign the <Response> (the <Assertion> always is)")
	requireConsent := fs.Bool("require-consent", false, "users approve the provider on a consent screen first")
	var certFiles, scopes, renames, roles, groups listFlag
	fs.Var(&certFiles, "cert-file", "PEM certificate of the provider (repeatable; added to those of the metadata)")
	fs.Var(&scopes, "scope", "ClientScopes (protocol saml2 or both) producing the attributes, comma separated")
	fs.Var(&renames, "rename", "attribute renames from=to, comma separated (Client.attribute_mappings)")
	fs.Var(&roles, "allow-role", "role whose members may use the provider (repeatable)")
	fs.Var(&groups, "allow-group", "group whose members may use the provider (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *metadataFile != "" && *metadataURL != "" {
		return usageError{"use --metadata-file or --metadata-url, not both"}
	}

	in := service.SAMLClientInput{
		Name:               *name,
		NameIDFormat:       *nameIDFormat,
		Pairwise:           *pairwise,
		WantResponseSigned: *wantResponseSigned,
		Scopes:             scopes,
		AllowRoles:         roles,
		AllowGroups:        groups,
		GrantedBy:          cliActor(),
		RequireConsent:     *requireConsent,
	}

	var md *samladapter.SPMetadata
	if *metadataFile != "" || *metadataURL != "" {
		data, err := readMetadata(ctx, *metadataFile, *metadataURL)
		if err != nil {
			return err
		}
		if md, err = samladapter.ParseSPMetadata(data); err != nil {
			return err
		}
		in.EntityID, in.ACSURL, in.SLOURL = md.EntityID, md.ACSURL, md.SLOURL
		if in.NameIDFormat == "" {
			in.NameIDFormat = md.NameIDFormat
		}
		for _, c := range md.Certificates {
			in.Certificates = append(in.Certificates, domain.ClientCertificate{PEM: c})
		}
	}
	// Explicit flags win over the metadata.
	if *entityID != "" {
		in.EntityID = *entityID
	}
	if *acsURL != "" {
		in.ACSURL = *acsURL
	}
	if *sloURL != "" {
		in.SLOURL = *sloURL
	}
	if in.EntityID == "" || in.ACSURL == "" {
		return usageError{"give --metadata-file / --metadata-url, or --entity-id and --acs-url"}
	}
	for _, f := range certFiles {
		pemText, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		in.Certificates = append(in.Certificates, domain.ClientCertificate{PEM: string(pemText)})
	}
	if len(renames) > 0 {
		in.AttributeMappings = map[string]string{}
		for _, r := range renames {
			from, to, ok := strings.Cut(r, "=")
			if !ok {
				return usageError{fmt.Sprintf("--rename %q: expected from=to", r)}
			}
			in.AttributeMappings[from] = to
		}
	}

	env, err := openSAMLEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()
	in.RealmID = env.realm.ID

	app, err := env.clients.Create(ctx, in)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "SAML client created: %s\n", app.EntityID)
	fmt.Fprintf(out, "  ACS URL:      %s\n", app.ACSURL)
	fmt.Fprintf(out, "  SLO URL:      %s\n", orDash(app.SLOURL))
	fmt.Fprintf(out, "  NameID:       %s\n", app.NameIDFormat)
	fmt.Fprintf(out, "  certificates: %s\n", describeCertificates(app))
	fmt.Fprintf(out, "  consent:      %s\n", consentLabel(app.RequireConsent))
	if len(app.ClientCertificates) == 0 {
		fmt.Fprintln(out, "  note: without a certificate, its requests are not signed: it can sign users in, but cannot use single logout")
	} else {
		fmt.Fprintln(out, "  note: every request it sends must now be signed with one of these certificates")
	}
	if md != nil {
		for _, w := range md.Warnings {
			fmt.Fprintf(out, "  metadata warning: %s\n", w)
		}
	}
	if len(roles) == 0 && len(groups) == 0 {
		fmt.Fprintln(out, "  warning: no --allow-role / --allow-group: nobody can use it yet (deny by default)")
	}
	fmt.Fprintf(out, "\nIdP metadata to give to the service provider: %s/r/%s/saml/metadata\n", devPublicURL(), env.realm.Name)
	return nil
}

func samlClientsAddCert(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("saml clients add-cert", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	entityID := fs.String("entity-id", "", "entity ID of the service provider (required)")
	certFile := fs.String("cert-file", "", "PEM certificate to add (required)")
	notBefore := fs.String("not-before", "", "accept it from this time (RFC 3339), e.g. when the provider switches")
	notAfter := fs.String("not-after", "", "stop accepting it at this time (RFC 3339)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entityID == "" || *certFile == "" {
		return usageError{"--entity-id and --cert-file are required"}
	}
	pemText, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	cert := domain.ClientCertificate{PEM: string(pemText)}
	if cert.NotBefore, err = parseOptionalTime("--not-before", *notBefore); err != nil {
		return err
	}
	if cert.NotAfter, err = parseOptionalTime("--not-after", *notAfter); err != nil {
		return err
	}
	env, err := openSAMLEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()
	app, err := env.clients.AddCertificate(ctx, env.realm.ID, *entityID, cert)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "certificates of %s: %s\n", app.EntityID, describeCertificates(app))
	return nil
}

func samlClientsRemoveCert(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("saml clients remove-cert", flag.ContinueOnError)
	realmName := fs.String("realm", "", "realm name (required)")
	entityID := fs.String("entity-id", "", "entity ID of the service provider (required)")
	fingerprint := fs.String("fingerprint", "", "SHA-256 fingerprint of the certificate, or its first 8+ hex digits (see list)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entityID == "" || *fingerprint == "" {
		return usageError{"--entity-id and --fingerprint are required"}
	}
	env, err := openSAMLEnv(ctx, *realmName)
	if err != nil {
		return err
	}
	defer env.client.Close()
	app, err := env.clients.RemoveCertificate(ctx, env.realm.ID, *entityID, *fingerprint)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "certificates of %s: %s\n", app.EntityID, describeCertificates(app))
	return nil
}

// readMetadata reads a metadata file, or fetches it once (short timeout,
// size limit): it is only data, parsed by ParseSPMetadata.
func readMetadata(ctx context.Context, file, rawURL string) ([]byte, error) {
	if file != "" {
		return os.ReadFile(file)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch metadata: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func describeCertificates(app *domain.ClientApp) string {
	certs, err := app.Certificates()
	if err != nil {
		return "INVALID: " + err.Error()
	}
	if len(certs) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(certs))
	for _, c := range certs {
		fp, err := service.CertificateFingerprint(c.PEM)
		if err != nil {
			fp = "unreadable"
		} else {
			fp = fp[:16]
		}
		window := ""
		if !c.NotBefore.IsZero() || !c.NotAfter.IsZero() {
			window = fmt.Sprintf(" [%s → %s]", fmtTime(c.NotBefore), fmtTime(c.NotAfter))
		}
		parts = append(parts, fp+window)
	}
	return strings.Join(parts, ", ")
}

func parseOptionalTime(flagName, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, usageError{fmt.Sprintf("%s: expected RFC 3339, e.g. 2026-11-01T00:00:00Z", flagName)}
	}
	return t, nil
}

func shortNameIDFormat(f string) string {
	switch f {
	case domain.NameIDFormatPersistent, "":
		return "persistent"
	case domain.NameIDFormatTransient:
		return "transient"
	case domain.NameIDFormatEmail:
		return "email"
	case domain.NameIDFormatUnspecified:
		return "unspecified"
	default:
		return f
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
