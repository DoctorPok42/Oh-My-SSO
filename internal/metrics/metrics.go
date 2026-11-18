// Package metrics exposes the Prometheus metrics of a server on a listener
// of its own (METRICS_ADDR), never on the public port: the requests of the
// public server, the audit events (sign-ins, failures, lockouts...), the
// tokens issued, the status of the dependencies, and the Go runtime's.
//
// Every label takes a bounded set of values (route patterns, the audit
// catalogue): a value a client chooses would let it create series at will.
package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sso.internal/sso/internal/health"
	"sso.internal/sso/internal/httptimeout"
)

var (
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "omsso_http_request_duration_seconds",
		Help:    "Duration of the public server's HTTP requests, by method, route pattern and status code.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "code"})

	auditEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "omsso_audit_events_total",
		Help: "Audit log entries written, by action (auth.login, auth.login_failed, user.locked...) and status.",
	}, []string{"action", "status"})

	tokensIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "omsso_tokens_issued_total",
		Help: "Tokens recorded, by type (access_token, refresh_token, saml_session).",
	}, []string{"type"})
)

const dependencyHelp = "1 when the dependency answers this server (the key manager with a real signature), " +
	"0 otherwise; absent when it is not configured."

var dependencyUp = prometheus.NewDesc("omsso_dependency_up", dependencyHelp, []string{"dependency"}, nil)

// checkTimeout: a dependency that does not answer in that time is down.
const checkTimeout = 3 * time.Second

// ObserveRequest records one request of the public server. route is its
// chi pattern ("/r/{realmName}/login"), "" when no route matched.
func ObserveRequest(method, route string, status int, d time.Duration) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		method = "other"
	}
	if route == "" {
		route = "unmatched" // the raw path would be one series per URL tried
	}
	requestDuration.WithLabelValues(method, route, strconv.Itoa(status)).Observe(d.Seconds())
}

// AuditEvent counts an audit log entry once written.
func AuditEvent(action, status string) { auditEvents.WithLabelValues(action, status).Inc() }

// TokenIssued counts a token once recorded.
func TokenIssued(tokenType string) { tokensIssued.WithLabelValues(tokenType).Inc() }

// Serve listens on addr and serves GET /metrics in the background, with
// omsso_dependency_up from deps (by label: "postgresql", "kms"...). It
// returns once listening, so that a wrong address stops the server at
// startup.
func Serve(addr string, deps map[string]func(context.Context) error) error {
	if err := prometheus.Register(dependencies(deps)); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	go func() { _ = httptimeout.NewServer(addr, mux, httptimeout.Admin).Serve(ln) }()
	return nil
}

// dependencies checks every dependency at each scrape, all at once.
type dependencies map[string]func(context.Context) error

func (d dependencies) Describe(ch chan<- *prometheus.Desc) { ch <- dependencyUp }

func (d dependencies) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for name, check := range d {
		wg.Go(func() {
			err := check(ctx)
			if errors.Is(err, health.ErrDisabled) {
				return
			}
			up := 0.0
			if err == nil {
				up = 1
			}
			ch <- prometheus.MustNewConstMetric(dependencyUp, prometheus.GaugeValue, up, name)
		})
	}
	wg.Wait()
}
