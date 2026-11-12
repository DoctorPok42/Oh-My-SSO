package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"sso.internal/sso/internal/health"
)

// runHealthcheck asks the Admin API running in this container whether it is
// ready: the HEALTHCHECK of the image, which has no shell nor curl.
func runHealthcheck() int {
	url, err := probeURL(adminAddr())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ADMIN_API_ADDR: %v\n", err)
		return 1
	}
	if err := health.Probe(context.Background(), url); err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	return 0
}

// probeURL is where the Admin API listening on addr (ADMIN_API_ADDR) answers
// from inside its container: the address it is bound to, or the loopback one
// when it listens on every address (":8090", "0.0.0.0:8090").
func probeURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/readyz", nil
}
