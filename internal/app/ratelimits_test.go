package app

import (
	"testing"
	"time"

	"sso.internal/sso/internal/httpserver"
)

func TestParseRateRule(t *testing.T) {
	for raw, want := range map[string]httpserver.RateRule{
		"600/1m":       {Max: 600, Window: time.Minute},
		" 10 / 15m ":   {Max: 10, Window: 15 * time.Minute},
		"1/30s":        {Max: 1, Window: 30 * time.Second},
		"5000/1h30m0s": {Max: 5000, Window: 90 * time.Minute},
	} {
		got, err := parseRateRule(raw)
		if err != nil || got != want {
			t.Errorf("parseRateRule(%q) = %+v, %v; want %+v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"600", "600/", "/1m", "0/1m", "-1/1m", "x/1m", "600/0s", "600/-1m", "600/60"} {
		if _, err := parseRateRule(raw); err == nil {
			t.Errorf("parseRateRule(%q): no error", raw)
		}
	}
}

func TestProtocolRateLimits(t *testing.T) {
	t.Setenv("RATE_LIMIT_OIDC_PER_IP", "")
	t.Setenv("RATE_LIMIT_OIDC_CLIENT_FAILURES_PER_IP", "")
	t.Setenv("RATE_LIMIT_SAML_PER_IP", "")
	if got := ProtocolRateLimits(); got != httpserver.DefaultProtocolLimits {
		t.Fatalf("without variables: %+v, want the defaults %+v", got, httpserver.DefaultProtocolLimits)
	}

	t.Setenv("RATE_LIMIT_OIDC_PER_IP", "6000/1m")
	got := ProtocolRateLimits()
	if got.OIDCPerIP != (httpserver.RateRule{Max: 6000, Window: time.Minute}) {
		t.Errorf("OIDCPerIP = %+v", got.OIDCPerIP)
	}
	if got.ClientFailuresPerIP != httpserver.DefaultProtocolLimits.ClientFailuresPerIP ||
		got.SAMLPerIP != httpserver.DefaultProtocolLimits.SAMLPerIP {
		t.Errorf("an unset variable must keep its default: %+v", got)
	}
}
