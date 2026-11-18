package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/migrate/migrations"
	"sso.internal/sso/internal/app"
	"sso.internal/sso/internal/clientip"
	"sso.internal/sso/internal/geoip"
	"sso.internal/sso/internal/keymanager"
	"sso.internal/sso/internal/storage/entstore"
)

// idp doctor checks every setting and dependency at once, one line each,
// where the server stops at the first wrong one, or fails only when it is
// first used. Run it with the environment of the server (docker compose
// exec idp /idp doctor).

const doctorUsage = `usage:
  idp doctor   check the settings and dependencies of this server, with its environment
`

// doctorCheckTimeout: each check, so a dependency that hangs cannot hold
// the others.
const doctorCheckTimeout = 10 * time.Second

// whatFailed: what was checked, then why it failed.
const whatFailed = "%s: %v"

// result of a check. OFF: not configured, on purpose.
type result struct{ status, detail string }

func pass(format string, a ...any) result { return result{"OK", fmt.Sprintf(format, a...)} }
func off(format string, a ...any) result  { return result{"OFF", fmt.Sprintf(format, a...)} }
func warn(format string, a ...any) result { return result{"WARN", fmt.Sprintf(format, a...)} }
func fail(format string, a ...any) result { return result{"FAIL", fmt.Sprintf(format, a...)} }

// doctor holds what a check finds for the next ones.
type doctor struct {
	db    *sql.DB // nil when out of reach: the checks that need it say so
	from  string  // SMTP_FROM, when SMTP is set
	https bool    // PUBLIC_URL is https
}

func runDoctor(args []string, out io.Writer) int {
	if len(args) > 0 {
		if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
			fmt.Fprint(out, doctorUsage)
			return 0
		}
		fmt.Fprint(os.Stderr, doctorUsage)
		return 2
	}
	// The report says it all: the log lines of the settings would cut through it.
	slog.SetDefault(slog.New(slog.DiscardHandler))

	var d doctor
	defer func() {
		if d.db != nil {
			d.db.Close()
		}
	}()
	checks := []struct {
		name string
		run  func(context.Context) result
	}{
		{"Database", d.database},
		{"Clock", d.clock},
		{"Valkey", checkValkey},
		{"Key manager", d.keyManager},
		{"SMTP", d.smtp},
		{"SPF", d.spf},
		{"DKIM", d.dkim},
		{"Public URL", d.publicURL},
		{"Proxies", d.proxies},
		{"GeoIP", checkGeoIP},
	}
	failed, warned := 0, 0
	for _, c := range checks {
		ctx, cancel := context.WithTimeout(context.Background(), doctorCheckTimeout)
		r := c.run(ctx)
		cancel()
		// One line per check: some errors span several (pgx lists each address tried).
		fmt.Fprintf(out, "%-4s  %-11s  %s\n", r.status, c.name, strings.Join(strings.Fields(r.detail), " "))
		switch r.status {
		case "FAIL":
			failed++
		case "WARN":
			warned++
		}
	}
	fmt.Fprintf(out, "\n%d failed, %d warning(s)\n", failed, warned)
	if failed > 0 {
		return 1
	}
	return 0
}

func (d *doctor) database(ctx context.Context) result {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		return fail("DATABASE_URL: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fail("%v", err)
	}
	d.db = db
	missing, unknown, err := entstore.CompareMigrations(ctx, db, migrations.Versions())
	switch {
	case err != nil:
		return fail("read the applied migrations: %v", err)
	case len(missing) > 0:
		return fail("%d migration(s) not applied, from %s: the servers refuse to start (apply them: the migrate service, make migrate-apply)",
			len(missing), missing[0])
	case len(unknown) > 0:
		return warn("schema ahead of this version: %d migration(s) it does not know, from %s", len(unknown), unknown[0])
	}
	return pass("schema up to date (%d migrations)", len(migrations.Versions()))
}

func (d *doctor) clock(ctx context.Context) result {
	if d.db == nil {
		return warn("not checked: needs the database")
	}
	sent := time.Now()
	var dbNow time.Time
	if err := d.db.QueryRowContext(ctx, "SELECT now()").Scan(&dbNow); err != nil {
		return fail("%v", err)
	}
	// The database read its clock about halfway through the round trip.
	return clockResult(sent.Add(time.Since(sent) / 2).Sub(dbNow))
}

// clockResult: TOTP codes change every 30 s and tokens carry their times:
// servers whose clocks disagree refuse each other's.
func clockResult(drift time.Duration) result {
	side := "ahead of"
	if drift < 0 {
		side = "behind"
	}
	msg := fmt.Sprintf("%s %s the database's clock", drift.Abs().Round(time.Millisecond), side)
	switch abs := drift.Abs(); {
	case abs > 30*time.Second:
		return fail("%s: TOTP codes and token times will be refused, synchronise the clocks (NTP)", msg)
	case abs > 5*time.Second:
		return warn("%s: synchronise the clocks (NTP)", msg)
	}
	return pass("%s", msg)
}

func checkValkey(ctx context.Context) result {
	c, err := app.OpenValkey()
	if err != nil {
		return fail("%v", err)
	}
	defer c.Close()
	if err := c.Do(ctx, c.B().Ping().Build()).Error(); err != nil {
		return fail("%v", err)
	}
	return pass("answers")
}

func (d *doctor) keyManager(ctx context.Context) result {
	// vault.New signs in (AppRole) without a context: a Vault that drops the
	// packets would hold this line for minutes. The goroutine is left behind.
	type built struct {
		km      keymanager.KeyManager
		backend string
		err     error
	}
	ch := make(chan built, 1)
	go func() {
		km, backend, err := app.NewKeyManager()
		ch <- built{km, backend, err}
	}()
	var b built
	select {
	case b = <-ch:
	case <-ctx.Done():
		return fail("%s: no answer in %s", os.Getenv("KEYMANAGER_BACKEND"), doctorCheckTimeout)
	}
	km, backend, err := b.km, b.backend, b.err
	if err != nil {
		return fail(whatFailed, backend, err)
	}
	if _, ok := km.(keymanager.Encrypter); !ok {
		return fail("%s cannot encrypt (TOTP secrets, links of queued e-mails)", backend)
	}
	if backend == app.BackendLocalDev {
		return warn("local_dev (development only): its keys live in the memory of each process, no signature to try from here")
	}
	if d.db == nil {
		return warn("%s: signature not tried, needs the database", backend)
	}
	client := ent.NewClient(ent.Driver(entstore.NewDriver(d.db)))
	err = app.SignWithKMS(ctx, km, entstore.NewRealmRepository(client), entstore.NewSigningKeyRepository(client))
	if err != nil {
		return fail(whatFailed, backend, err)
	}
	return pass("%s: signed with the master realm's key", backend)
}

func (d *doctor) smtp(ctx context.Context) result {
	sender, err := app.SMTPSender(app.Templates())
	if err != nil {
		return fail("%v", err)
	}
	if sender == nil {
		if os.Getenv("APP_ENV") == "development" {
			return off("SMTP_HOST is not set: e-mails are printed in the server's log (development only)")
		}
		return off("SMTP_HOST is not set: no e-mail is sent, \"forgot password\" is disabled")
	}
	cfg := sender.Config()
	d.from = cfg.From
	where := fmt.Sprintf("%s:%d (%s)", cfg.Host, cfg.Port, cfg.Security)
	if err := sender.Verify(ctx); err != nil {
		return fail(whatFailed, where, err)
	}
	if cfg.Username == "" {
		return pass("%s: connected, no AUTH (SMTP_USERNAME is not set)", where)
	}
	return pass("%s: connected and signed in as %s", where, cfg.Username)
}

// sendingDomain is the domain of SMTP_FROM, "" without SMTP or without a
// public domain (no-reply@localhost in development: no DNS to read).
func (d *doctor) sendingDomain() string {
	a, err := mail.ParseAddress(d.from)
	if err != nil {
		return ""
	}
	if domain := a.Address[strings.LastIndexByte(a.Address, '@')+1:]; strings.Contains(domain, ".") {
		return domain
	}
	return ""
}

func (d *doctor) spf(ctx context.Context) result {
	domain := d.sendingDomain()
	if domain == "" {
		return off("no SMTP, or SMTP_FROM has no public domain")
	}
	txt, err := net.DefaultResolver.LookupTXT(ctx, domain)
	return spfResult(domain, txt, err)
}

// spfResult: without exactly one SPF record (RFC 7208: two are an error),
// receivers may take the e-mails for spam. Whether it allows SMTP_HOST
// cannot be told from here: the relay's sending address is not known.
func spfResult(domain string, txt []string, err error) result {
	var dnsErr *net.DNSError
	if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
		return warn("%s: DNS lookup failed: %v", domain, err)
	}
	var spf []string
	for _, r := range txt {
		if l := strings.ToLower(r); l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			spf = append(spf, r)
		}
	}
	switch len(spf) {
	case 0:
		return warn("%s has no SPF record: its e-mails are likely taken for spam", domain)
	case 1:
		return pass("%s: %s", domain, spf[0])
	}
	return warn("%s has %d SPF records: receivers treat that as an error, keep one", domain, len(spf))
}

// dkimSelectors: the ones providers use most. The selector that signs for
// SMTP_FROM cannot be known from here: none found is a warning only.
var dkimSelectors = []string{"default", "dkim", "mail", "selector1", "selector2", "google", "k1", "s1", "s2", "smtp"}

func (d *doctor) dkim(ctx context.Context) result {
	domain := d.sendingDomain()
	if domain == "" {
		return off("no SMTP, or SMTP_FROM has no public domain")
	}
	for _, sel := range dkimSelectors {
		txt, _ := net.DefaultResolver.LookupTXT(ctx, sel+"._domainkey."+domain)
		if slices.ContainsFunc(txt, func(r string) bool { return strings.Contains(r, "p=") }) {
			return pass("%s: key found under selector %q", domain, sel)
		}
	}
	return warn("%s: no DKIM key under the usual selectors (%s): check that your mail provider signs with this domain",
		domain, strings.Join(dkimSelectors, ", "))
}

func (d *doctor) publicURL(ctx context.Context) result {
	prod := os.Getenv("APP_ENV") == "production"
	raw := strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	if raw == "" {
		if prod {
			return fail("not set: required when APP_ENV=production")
		}
		return warn("not set: http://localhost:%s is used (development only)", app.IdPPort())
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fail("%q is not an http(s) URL", raw)
	}
	d.https = u.Scheme == "https"
	if !d.https && prod {
		return fail("%s is not https: sessions and tokens would travel in clear", raw)
	}

	// The master realm's OIDC discovery: the URL leads to a server of this
	// deployment, which announces the same issuer.
	issuer := raw + "/r/master"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return fail("%v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &certErr):
		return fail("%s: TLS certificate refused: %v", raw, certErr.Err)
	case err != nil:
		return warn("not reachable from here: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail("%s answered %s", req.URL, resp.Status)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fail("%s is not an OIDC discovery document: %v", req.URL, err)
	}
	if doc.Issuer != issuer {
		return fail("the server there announces the issuer %s, not %s: it runs with another PUBLIC_URL", doc.Issuer, issuer)
	}
	if resp.TLS == nil {
		return pass("%s answers with the expected issuer (no TLS)", raw)
	}
	// ACME renews a month before the end: two weeks left means it failed.
	notAfter := resp.TLS.PeerCertificates[0].NotAfter
	if time.Until(notAfter) < 14*24*time.Hour {
		return warn("%s: the TLS certificate expires on %s, check its renewal", raw, notAfter.UTC().Format(time.DateOnly))
	}
	return pass("%s answers with the expected issuer, TLS certificate valid until %s", raw, notAfter.UTC().Format(time.DateOnly))
}

func (d *doctor) proxies(context.Context) result {
	raw := os.Getenv("TRUSTED_PROXIES")
	res, err := clientip.Parse(raw, os.Getenv("CLIENT_IP_HEADER"))
	if err != nil {
		return fail("%v", err)
	}
	return proxiesResult(raw, res, d.https)
}

// proxiesResult: a trusted proxy sets the client address that rate limits,
// lockout, IP allowlists and the audit log use.
func proxiesResult(raw string, res clientip.Resolver, https bool) result {
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); strings.HasSuffix(p, "/0") {
			return fail("TRUSTED_PROXIES has %s, every address: any client can choose the IP it is seen from", p)
		}
	}
	if !res.TrustsProxies() && https {
		return warn("TRUSTED_PROXIES is empty while PUBLIC_URL is https: idp serves plain HTTP, so a proxy is in front " +
			"and every request seems to come from it (shared rate limits, audit addresses)")
	}
	return pass("%s", strings.TrimPrefix(res.String(), "client ip: "))
}

func checkGeoIP(context.Context) result {
	path := os.Getenv("GEOIP_DB_PATH")
	if path == "" {
		return off("GEOIP_DB_PATH is not set: no \"new country\" signal on sign-ins")
	}
	r, err := geoip.Open(path)
	if err != nil {
		return fail("%v", err)
	}
	defer r.Close()
	if age := time.Since(r.BuiltAt()); age > 60*24*time.Hour {
		return warn("%s: %d days old, update it", r.Description(), int(age.Hours()/24))
	}
	return pass("%s", r.Description())
}
