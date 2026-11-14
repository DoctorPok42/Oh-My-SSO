package app

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	vk "github.com/valkey-io/valkey-go"

	valkeycache "sso.internal/sso/internal/cache/valkey"
)

// ValkeyOptions reads how to reach Valkey:
//
//	VALKEY_ADDR=valkey:6379            host:port; several, comma separated: nodes of a
//	                                   cluster, or the sentinels with VALKEY_SENTINEL_MASTER
//	VALKEY_USERNAME=                   ACL user (default: "default", the requirepass user)
//	VALKEY_PASSWORD=                   required when APP_ENV=production
//	VALKEY_TLS=true                    TLS; the certificate must match the host name
//	VALKEY_TLS_CA_FILE=/certs/ca.pem   with VALKEY_TLS: a private CA instead of the system's
//	VALKEY_SENTINEL_MASTER=mymaster    Sentinel: the name of the master the sentinels watch
//	VALKEY_SENTINEL_PASSWORD=          the sentinels' own password, if they have one
//	VALKEY_DB=0                        logical database (SELECT), on a shared server
func ValkeyOptions() (valkeycache.Options, error) {
	return valkeyOptionsFrom(os.Getenv)
}

func valkeyOptionsFrom(getenv func(string) string) (valkeycache.Options, error) {
	var o valkeycache.Options
	for _, a := range strings.Split(getenv("VALKEY_ADDR"), ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		host, port, err := net.SplitHostPort(a)
		if err != nil || host == "" || strings.ContainsAny(host, "/@") { // no scheme, no credentials
			return o, fmt.Errorf("VALKEY_ADDR: %q is not host:port", a)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return o, fmt.Errorf("VALKEY_ADDR: %q has no valid port", a)
		}
		o.Addresses = append(o.Addresses, a)
	}
	if len(o.Addresses) == 0 {
		return o, errors.New("VALKEY_ADDR is not set (host:port of Valkey)")
	}

	o.Username = getenv("VALKEY_USERNAME")
	o.Password = getenv("VALKEY_PASSWORD")
	if o.Username != "" && o.Password == "" {
		return o, errors.New("VALKEY_USERNAME is set without VALKEY_PASSWORD")
	}
	if o.Password == "" && getenv("APP_ENV") == "production" {
		return o, errors.New("VALKEY_PASSWORD is required when APP_ENV=production: any container of Valkey's " +
			"network could otherwise read and change sign-in state (docs/PRODUCTION.md)")
	}

	useTLS := false
	if v := getenv("VALKEY_TLS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return o, fmt.Errorf("VALKEY_TLS %q must be true or false", v)
		}
		useTLS = b
	}
	caFile := getenv("VALKEY_TLS_CA_FILE")
	switch {
	case caFile != "" && !useTLS:
		return o, errors.New("VALKEY_TLS_CA_FILE is set but VALKEY_TLS is not true")
	case useTLS:
		o.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return o, fmt.Errorf("VALKEY_TLS_CA_FILE: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return o, fmt.Errorf("VALKEY_TLS_CA_FILE %s holds no PEM certificate", caFile)
			}
			o.TLS.RootCAs = pool
		}
	}

	o.SentinelMaster = getenv("VALKEY_SENTINEL_MASTER")
	o.SentinelPassword = getenv("VALKEY_SENTINEL_PASSWORD")
	if o.SentinelPassword != "" && o.SentinelMaster == "" {
		return o, errors.New("VALKEY_SENTINEL_PASSWORD is set without VALKEY_SENTINEL_MASTER")
	}

	if v := getenv("VALKEY_DB"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return o, fmt.Errorf("VALKEY_DB %q must be a whole number of at least 0", v)
		}
		o.DB = n
	}
	return o, nil
}

// describeValkey is o for the startup log, without the secrets.
func describeValkey(o valkeycache.Options) string {
	var b strings.Builder
	b.WriteString(strings.Join(o.Addresses, ","))
	if o.SentinelMaster != "" {
		b.WriteString(" (sentinels of " + o.SentinelMaster + ")")
	}
	if o.DB != 0 {
		b.WriteString(", db " + strconv.Itoa(o.DB))
	}
	switch {
	case o.Username != "":
		b.WriteString(", user " + o.Username)
	case o.Password != "":
		b.WriteString(", password")
	default:
		b.WriteString(", no password")
	}
	if o.TLS != nil {
		b.WriteString(", TLS")
	} else {
		b.WriteString(", no TLS")
	}
	return b.String()
}

// OpenValkey connects to Valkey with the settings of ValkeyOptions.
func OpenValkey() (vk.Client, error) {
	o, err := ValkeyOptions()
	if err != nil {
		return nil, err
	}
	c, err := valkeycache.Open(o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", describeValkey(o), err)
	}
	return c, nil
}

// mustOpenValkey is OpenValkey for the servers: a wrong setting or a
// Valkey that does not answer at startup stops them.
func mustOpenValkey() vk.Client {
	o, err := ValkeyOptions()
	if err != nil {
		log.Fatalf("valkey: %v", err)
	}
	c, err := valkeycache.Open(o)
	if err != nil {
		log.Fatalf("valkey: %s: %v", describeValkey(o), err)
	}
	log.Printf("valkey: %s", describeValkey(o))
	return c
}
