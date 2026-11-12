package main

import (
	"context"
	"fmt"
	"os"

	"sso.internal/sso/internal/app"
	"sso.internal/sso/internal/health"
)

// runHealthcheck asks the server running in this container whether it is
// ready: the HEALTHCHECK of the image, which has no shell nor curl.
func runHealthcheck() int {
	if err := health.Probe(context.Background(), "http://127.0.0.1:"+app.IdPPort()+"/readyz"); err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	return 0
}
