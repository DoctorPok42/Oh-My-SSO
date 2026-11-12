package app

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"sso.internal/sso/internal/httpserver"
)

// ProtocolRateLimits reads the rate limits of the protocol endpoints of
// cmd/idp, each as <max>/<window> (a Go duration: 30s, 1m, 15m, 1h):
//
//	RATE_LIMIT_OIDC_PER_IP=600/1m                  /token, /introspect, /revoke: requests per
//	                                               address that authenticate no client
//	RATE_LIMIT_OIDC_CLIENT_FAILURES_PER_IP=10/15m  failed authentications of one client_id
//	                                               from one address
//	RATE_LIMIT_SAML_PER_IP=300/1m                  /saml/sso, /login, /consent, /slo: requests
//	                                               per address
//	RATE_LIMIT_LOGIN_FAILURES_PER_IP=20/15m        failed sign-ins (password or passkey) from
//	                                               one address
//
// An unset variable keeps the default of the code
// (httpserver.DefaultProtocolLimits); an invalid one stops the server.
func ProtocolRateLimits() httpserver.ProtocolLimits {
	l := httpserver.DefaultProtocolLimits
	for _, v := range []struct {
		name string
		rule *httpserver.RateRule
	}{
		{"RATE_LIMIT_OIDC_PER_IP", &l.OIDCPerIP},
		{"RATE_LIMIT_OIDC_CLIENT_FAILURES_PER_IP", &l.ClientFailuresPerIP},
		{"RATE_LIMIT_SAML_PER_IP", &l.SAMLPerIP},
		{"RATE_LIMIT_LOGIN_FAILURES_PER_IP", &l.LoginFailuresPerIP},
	} {
		raw := os.Getenv(v.name)
		if raw == "" {
			continue
		}
		rule, err := parseRateRule(raw)
		if err != nil {
			log.Fatalf("%s %q: %v", v.name, raw, err)
		}
		*v.rule = rule
	}
	log.Printf("rate limits: OIDC %s per address, %s client failures per address, SAML %s per address, %s failed sign-ins per address",
		l.OIDCPerIP, l.ClientFailuresPerIP, l.SAMLPerIP, l.LoginFailuresPerIP)
	return l
}

// parseRateRule reads <max>/<window>: a whole number of at least 1 and a
// positive Go duration.
func parseRateRule(raw string) (httpserver.RateRule, error) {
	maxPart, windowPart, ok := strings.Cut(strings.TrimSpace(raw), "/")
	if !ok {
		return httpserver.RateRule{}, fmt.Errorf("must be <max>/<window>, e.g. 600/1m")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(maxPart), 10, 64)
	if err != nil || n < 1 {
		return httpserver.RateRule{}, fmt.Errorf("the maximum must be a whole number of at least 1")
	}
	window, err := time.ParseDuration(strings.TrimSpace(windowPart))
	if err != nil || window <= 0 {
		return httpserver.RateRule{}, fmt.Errorf("the window must be a positive duration such as 30s, 1m or 15m")
	}
	return httpserver.RateRule{Max: n, Window: window}, nil
}
