// Package metrics records agent synchronization state and exposes it in the
// Prometheus text format. Labels come only from configured bundle names, so a
// gateway response cannot create new time series.
package metrics

import (
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"kube-secret-gateway-agent/internal/config"
)

const prefix = "kube_secret_gateway_agent_"

// Metrics owns the agent's isolated Prometheus registry.
type Metrics struct {
	registry    *prometheus.Registry
	attempts    *prometheus.CounterVec
	errors      *prometheus.CounterVec
	changes     *prometheus.CounterVec
	healthy     *prometheus.GaugeVec
	lastAttempt *prometheus.GaugeVec
	lastSuccess *prometheus.GaugeVec
	lastChange  *prometheus.GaugeVec
	duration    *prometheus.HistogramVec
}

// New registers process, Go runtime and per-bundle collectors. It initializes
// every configured bundle so it appears on the first scrape, before any sync.
func New(bundles []config.Bundle, version string) (*Metrics, error) {
	labels := []string{"bundle"}
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		attempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "sync_attempts_total",
			Help: "Bundle synchronization attempts.",
		}, labels),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "sync_errors_total",
			Help: "Bundle synchronization attempts that failed.",
		}, labels),
		changes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "changes_total",
			Help: "Successful bundle synchronizations that installed changed files.",
		}, labels),
		healthy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "bundle_healthy",
			Help: "Whether the bundle's latest synchronization attempt succeeded (1) or failed or has not run (0).",
		}, labels),
		lastAttempt: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "last_attempt_timestamp_seconds",
			Help: "Unix time of the latest bundle synchronization attempt; 0 if none.",
		}, labels),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "last_successful_sync_timestamp_seconds",
			Help: "Unix time of the latest successful bundle synchronization, including an unchanged response; 0 if none.",
		}, labels),
		lastChange: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: prefix + "last_change_timestamp_seconds",
			Help: "Unix time files were last installed successfully for the bundle; 0 if never.",
		}, labels),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    prefix + "sync_duration_seconds",
			Help:    "Duration of bundle synchronization attempts.",
			Buckets: prometheus.DefBuckets,
		}, labels),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: prefix + "build_info",
		Help: "Build information for kube-secret-gateway-agent.",
	}, []string{"version"})
	buildInfo.WithLabelValues(version).Set(1)

	if err := errors.Join(
		m.registry.Register(collectors.NewGoCollector()),
		m.registry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})),
		m.registry.Register(buildInfo),
		m.registry.Register(m.attempts),
		m.registry.Register(m.errors),
		m.registry.Register(m.changes),
		m.registry.Register(m.healthy),
		m.registry.Register(m.lastAttempt),
		m.registry.Register(m.lastSuccess),
		m.registry.Register(m.lastChange),
		m.registry.Register(m.duration),
	); err != nil {
		return nil, err
	}

	for _, b := range bundles {
		m.attempts.WithLabelValues(b.Name).Add(0)
		m.errors.WithLabelValues(b.Name).Add(0)
		m.changes.WithLabelValues(b.Name).Add(0)
		m.healthy.WithLabelValues(b.Name).Set(0)
		m.lastAttempt.WithLabelValues(b.Name).Set(0)
		m.lastSuccess.WithLabelValues(b.Name).Set(0)
		m.lastChange.WithLabelValues(b.Name).Set(0)
		m.duration.WithLabelValues(b.Name)
	}
	return m, nil
}

// ObserveSync implements fetch.Observer.
func (m *Metrics) ObserveSync(bundle string, changed bool, err error, duration time.Duration) {
	now := float64(time.Now().UnixNano()) / 1e9
	m.attempts.WithLabelValues(bundle).Inc()
	m.lastAttempt.WithLabelValues(bundle).Set(now)
	m.duration.WithLabelValues(bundle).Observe(duration.Seconds())
	if err != nil {
		m.errors.WithLabelValues(bundle).Inc()
		m.healthy.WithLabelValues(bundle).Set(0)
		return
	}
	m.healthy.WithLabelValues(bundle).Set(1)
	m.lastSuccess.WithLabelValues(bundle).Set(now)
	if changed {
		m.changes.WithLabelValues(bundle).Inc()
		m.lastChange.WithLabelValues(bundle).Set(now)
	}
}

// Handler serves this registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
