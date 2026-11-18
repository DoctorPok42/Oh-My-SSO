// Package metricstest reads the metrics of internal/metrics in tests, from
// the default registry they are registered in. Tests only.
package metricstest

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Value sums the series of metric name whose labels include labels: a
// counter's value, a histogram's count of observations. The metrics are
// global: compare a value before and after, never an absolute one.
func Value(t testing.TB, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			matched := 0
			for _, l := range m.GetLabel() {
				if v, ok := labels[l.GetName()]; ok && v == l.GetValue() {
					matched++
				}
			}
			if matched == len(labels) {
				sum += m.GetCounter().GetValue() + float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return sum
}
