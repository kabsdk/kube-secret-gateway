// Package metrics exposes the gateway's state as Prometheus metrics.
//
// Secret state metrics are computed at scrape time from the resource cache,
// which the watches keep current. A Secret that disappears is therefore
// visible on the next scrape, without any client having to request it.
//
// Label values come only from configuration (exposure names, namespaces,
// Secret names, configured keys) or from small fixed sets (HTTP status
// codes, response reasons). Nothing a client sends can create a new series.
package metrics

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"kube-secret-gateway/internal/auth"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/resources"
)

const prefix = "kube_secret_gateway_"

// UnknownExposure is the exposure label of requests that do not resolve to a
// configured exposure. It cannot collide with an exposure name because those
// are RFC 1123 subdomains, which cannot contain '_'.
const UnknownExposure = "_unknown"

// State is the read-only view of the resource cache the metrics need.
type State interface {
	Secret(ref exposure.SecretRef) resources.Secret
	Statuses() []resources.Status
}

// Metrics owns the Prometheus registry.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	names    map[string]struct{}
}

// New registers all collectors on a dedicated registry.
func New(exposures []exposure.Exposure, state State) (*Metrics, error) {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "http_requests_total",
			Help: `HTTP requests to the exposure endpoint by exposure, status code and reason. Requests not matching a configured exposure are counted as exposure="` + UnknownExposure + `". The reason distinguishes outcomes that clients deliberately see as the same status, such as an unknown exposure and a client outside allowedCidrs (both 404).`,
		}, []string{"exposure", "status", "reason"}),
		names: make(map[string]struct{}, len(exposures)),
	}
	for i := range exposures {
		m.names[exposures[i].Name] = struct{}{}
	}
	err := errors.Join(
		m.registry.Register(collectors.NewGoCollector()),
		m.registry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})),
		m.registry.Register(m.requests),
		m.registry.Register(&stateCollector{exposures: exposures, state: state}),
	)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ObserveRequest counts one exposure endpoint request. Exposure names that are
// not configured are folded into UnknownExposure, so arbitrary request paths
// cannot create series. The reason must come from a fixed set of constants,
// never from request data.
func (m *Metrics) ObserveRequest(name string, status int, reason string) {
	if _, ok := m.names[name]; !ok {
		name = UnknownExposure
	}
	code := "other"
	if status >= 100 && status <= 599 {
		code = strconv.Itoa(status)
	}
	m.requests.WithLabelValues(name, code, reason).Inc()
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry returns the underlying registry.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

var (
	exposureRefLabels = []string{"exposure", "namespace", "secret"}
	resourceLabels    = []string{"namespace", "secret"}

	sourcePresentDesc = prometheus.NewDesc(prefix+"source_secret_present",
		"Whether the exposure's source Secret currently exists (1), or is absent or not yet synchronized (0).",
		exposureRefLabels, nil)
	authPresentDesc = prometheus.NewDesc(prefix+"auth_secret_present",
		"Whether the exposure's authentication Secret currently exists.",
		exposureRefLabels, nil)
	authValidDesc = prometheus.NewDesc(prefix+"auth_secret_valid",
		"Whether the exposure's authentication Secret exists and contains usable credentials (non-empty username and password).",
		exposureRefLabels, nil)
	expectedKeyDesc = prometheus.NewDesc(prefix+"expected_key_present",
		"Whether a configured exposure key is present in its source Secret.",
		[]string{"exposure", "key"}, nil)
	exposureHealthyDesc = prometheus.NewDesc(prefix+"exposure_healthy",
		"Whether the exposure can serve requests: source Secret present, authentication Secret valid and every configured key present.",
		[]string{"exposure"}, nil)
	watchConnectedDesc = prometheus.NewDesc(prefix+"watch_connected",
		"Whether a watch on the Secret is currently established.",
		resourceLabels, nil)
	lastSyncDesc = prometheus.NewDesc(prefix+"last_successful_sync_timestamp_seconds",
		"Unix time of the last successful full retrieval of the Secret's state (list or reconciliation); 0 if never.",
		resourceLabels, nil)
	watchErrorsDesc = prometheus.NewDesc(prefix+"watch_errors_total",
		"Watch failures for the Secret: failed watch requests, error events and unexpected events.",
		resourceLabels, nil)
	syncErrorsDesc = prometheus.NewDesc(prefix+"sync_errors_total",
		"Failed list or reconciliation requests for the Secret.",
		resourceLabels, nil)
)

// stateCollector derives Secret state metrics from the cache at scrape time.
type stateCollector struct {
	exposures []exposure.Exposure
	state     State
}

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		sourcePresentDesc, authPresentDesc, authValidDesc, expectedKeyDesc, exposureHealthyDesc,
		watchConnectedDesc, lastSyncDesc, watchErrorsDesc, syncErrorsDesc,
	} {
		ch <- d
	}
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	for _, st := range c.state.Statuses() {
		ns, name := st.Ref.Namespace, st.Ref.Name
		var lastSync float64
		if !st.LastSuccessfulSync.IsZero() {
			lastSync = float64(st.LastSuccessfulSync.UnixNano()) / 1e9
		}
		ch <- prometheus.MustNewConstMetric(watchConnectedDesc, prometheus.GaugeValue, boolValue(st.WatchConnected), ns, name)
		ch <- prometheus.MustNewConstMetric(lastSyncDesc, prometheus.GaugeValue, lastSync, ns, name)
		ch <- prometheus.MustNewConstMetric(watchErrorsDesc, prometheus.CounterValue, float64(st.WatchErrors), ns, name)
		ch <- prometheus.MustNewConstMetric(syncErrorsDesc, prometheus.CounterValue, float64(st.SyncErrors), ns, name)
	}

	for i := range c.exposures {
		e := &c.exposures[i]
		src := c.state.Secret(e.Source)
		authSecret := c.state.Secret(e.Auth.SecretRef)
		authValid := false
		if authSecret.Present {
			_, err := auth.NewBasic(authSecret.Data)
			authValid = err == nil
		}
		healthy := src.Present && authValid

		ch <- prometheus.MustNewConstMetric(sourcePresentDesc, prometheus.GaugeValue, boolValue(src.Present),
			e.Name, e.Source.Namespace, e.Source.Name)
		ch <- prometheus.MustNewConstMetric(authPresentDesc, prometheus.GaugeValue, boolValue(authSecret.Present),
			e.Name, e.Auth.SecretRef.Namespace, e.Auth.SecretRef.Name)
		ch <- prometheus.MustNewConstMetric(authValidDesc, prometheus.GaugeValue, boolValue(authValid),
			e.Name, e.Auth.SecretRef.Namespace, e.Auth.SecretRef.Name)
		for _, key := range e.Keys {
			_, present := src.Data[key]
			healthy = healthy && present
			ch <- prometheus.MustNewConstMetric(expectedKeyDesc, prometheus.GaugeValue, boolValue(present), e.Name, key)
		}
		ch <- prometheus.MustNewConstMetric(exposureHealthyDesc, prometheus.GaugeValue, boolValue(healthy), e.Name)
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
