package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"sso.internal/sso/internal/health"
)

func TestObserveRequestBoundsLabels(t *testing.T) {
	ObserveRequest("PROPFIND", "", 404, time.Millisecond)
	ObserveRequest("GET", "/r/{realmName}/login", 200, time.Millisecond)

	// WithLabelValues creates a series that does not exist: two series in
	// the end means these two are the only ones.
	requestDuration.WithLabelValues("other", "unmatched", "404")
	requestDuration.WithLabelValues("GET", "/r/{realmName}/login", "200")
	if n := testutil.CollectAndCount(requestDuration); n != 2 {
		t.Fatalf("%d series, want 2: a method or a path chosen by the client made its own", n)
	}
}

func TestDependencies(t *testing.T) {
	d := dependencies{
		"up":       func(context.Context) error { return nil },
		"down":     func(context.Context) error { return errors.New("refused") },
		"disabled": func(context.Context) error { return health.ErrDisabled },
	}
	want := "# HELP omsso_dependency_up " + dependencyHelp + "\n# TYPE omsso_dependency_up gauge\n" +
		"omsso_dependency_up{dependency=\"down\"} 0\nomsso_dependency_up{dependency=\"up\"} 1\n"
	if err := testutil.CollectAndCompare(d, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}
