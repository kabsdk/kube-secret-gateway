package server_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/resources"
	"kube-secret-gateway/internal/server"
)

var scrapeRef = exposure.SecretRef{Namespace: "monitoring", Name: "scrape-credentials"}

// stubMetrics stands in for the Prometheus handler.
var stubMetrics = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "kube_secret_gateway_stub 1\n")
})

type metricsFixture struct {
	handler http.Handler
	ready   *atomic.Bool
	source  *staticSource
	logs    *lockedBuffer
}

func newMetricsFixture(t *testing.T, withAuth bool) *metricsFixture {
	t.Helper()
	f := &metricsFixture{ready: &atomic.Bool{}, source: &staticSource{}, logs: &lockedBuffer{}}
	f.ready.Store(true)
	opts := server.MetricsOptions{
		Metrics: stubMetrics,
		Ready:   f.ready.Load,
		Secrets: f.source,
		Logger:  slog.New(slog.NewJSONHandler(f.logs, nil)),
	}
	if withAuth {
		opts.Auth = &exposure.Auth{Type: exposure.AuthBasic, SecretRef: scrapeRef}
	}
	h, err := server.NewMetricsHandler(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.handler = h
	return f
}

func (f *metricsFixture) do(method, path string, opts ...reqOption) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

func TestMetricsListenerRoutes(t *testing.T) {
	f := newMetricsFixture(t, false)

	rec := f.do(http.MethodGet, "/healthz")
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.String() != "ok\n" {
		t.Fatalf("healthz body = %q", rec.Body.String())
	}
	expectStatus(t, f.do(http.MethodGet, "/readyz"), http.StatusOK)
	rec = f.do(http.MethodGet, "/metrics")
	expectStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "kube_secret_gateway_stub") {
		t.Fatal("metrics not served")
	}

	f.ready.Store(false)
	expectStatus(t, f.do(http.MethodGet, "/readyz"), http.StatusServiceUnavailable)
	expectStatus(t, f.do(http.MethodGet, "/healthz"), http.StatusOK)

	for _, p := range []string{"/", "/secrets/my-cert/tls.crt", "/metrics/", "/healthz/", "/%6detrics", "/metrics/../metrics"} {
		expectStatus(t, f.do(http.MethodGet, p), http.StatusNotFound)
	}
	expectStatus(t, f.do(http.MethodPost, "/metrics"), http.StatusMethodNotAllowed)
	expectStatus(t, f.do(http.MethodHead, "/healthz"), http.StatusOK)
}

func TestMetricsAuthentication(t *testing.T) {
	f := newMetricsFixture(t, true)

	// Probes never need credentials, whatever state the auth Secret is in.
	probesOpen := func() {
		t.Helper()
		expectStatus(t, f.do(http.MethodGet, "/healthz"), http.StatusOK)
		expectStatus(t, f.do(http.MethodGet, "/readyz"), http.StatusOK)
	}

	// Authentication Secret missing, then malformed: operational failure.
	expectStatus(t, f.do(http.MethodGet, "/metrics", withAuth("prometheus", "scrape-pass")), http.StatusServiceUnavailable)
	probesOpen()
	f.source.set(scrapeRef, map[string][]byte{"username": []byte("prometheus")})
	expectStatus(t, f.do(http.MethodGet, "/metrics", withAuth("prometheus", "scrape-pass")), http.StatusServiceUnavailable)

	f.source.set(scrapeRef, credentials("prometheus", "scrape-pass"))
	for _, opt := range []reqOption{func(*http.Request) {}, withAuth("prometheus", "wrong"), withAuth("someone", "scrape-pass")} {
		rec := f.do(http.MethodGet, "/metrics", opt)
		expectStatus(t, rec, http.StatusUnauthorized)
		if rec.Header().Get("WWW-Authenticate") != `Basic realm="kube-secret-gateway"` {
			t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
		}
		if strings.Contains(rec.Body.String(), "kube_secret_gateway_stub") {
			t.Fatal("metrics served without valid credentials")
		}
	}
	rec := f.do(http.MethodGet, "/metrics", withAuth("prometheus", "scrape-pass"))
	expectStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "kube_secret_gateway_stub") {
		t.Fatal("metrics not served with valid credentials")
	}
	probesOpen()

	// Rotation takes effect with the next request.
	f.source.set(scrapeRef, credentials("prometheus", "rotated-pass"))
	expectStatus(t, f.do(http.MethodGet, "/metrics", withAuth("prometheus", "scrape-pass")), http.StatusUnauthorized)
	expectStatus(t, f.do(http.MethodGet, "/metrics", withAuth("prometheus", "rotated-pass")), http.StatusOK)

	for _, leaked := range []string{"scrape-pass", "rotated-pass", "Basic "} {
		if strings.Contains(f.logs.String(), leaked) {
			t.Fatalf("logs contain %q", leaked)
		}
	}
}

func TestNewMetricsHandlerRejectsIncompleteOptions(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ready := func() bool { return true }
	for name, opts := range map[string]server.MetricsOptions{
		"empty":           {},
		"no metrics":      {Ready: ready, Logger: logger},
		"no ready":        {Metrics: stubMetrics, Logger: logger},
		"auth no secrets": {Metrics: stubMetrics, Ready: ready, Logger: logger, Auth: &exposure.Auth{Type: exposure.AuthBasic, SecretRef: scrapeRef}},
	} {
		if _, err := server.NewMetricsHandler(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// staticSource is a SecretSource whose state tests set directly.
type staticSource struct {
	mu      sync.Mutex
	secrets map[exposure.SecretRef]resources.Secret
}

func (s *staticSource) Secret(ref exposure.SecretRef) resources.Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets[ref]
}

func (s *staticSource) set(ref exposure.SecretRef, data map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secrets == nil {
		s.secrets = make(map[exposure.SecretRef]resources.Secret)
	}
	s.secrets[ref] = resources.Secret{Present: true, Synced: true, Data: data}
}
