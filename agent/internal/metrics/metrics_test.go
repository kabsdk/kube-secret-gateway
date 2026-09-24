package metrics_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway-agent/internal/config"
	"kube-secret-gateway-agent/internal/metrics"
)

func TestMetricsDescribeBundleState(t *testing.T) {
	m, err := metrics.New([]config.Bundle{{Name: "nginx-tls"}}, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	// One changed success, one unchanged success and one error exercise every
	// state transition. The last result determines the health gauge.
	m.ObserveSync("nginx-tls", true, nil, 100*time.Millisecond)
	m.ObserveSync("nginx-tls", false, nil, 50*time.Millisecond)
	m.ObserveSync("nginx-tls", false, errors.New("gateway unavailable"), 25*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`kube_secret_gateway_agent_build_info{version="test-version"} 1`,
		`kube_secret_gateway_agent_sync_attempts_total{bundle="nginx-tls"} 3`,
		`kube_secret_gateway_agent_sync_errors_total{bundle="nginx-tls"} 1`,
		`kube_secret_gateway_agent_changes_total{bundle="nginx-tls"} 1`,
		`kube_secret_gateway_agent_bundle_healthy{bundle="nginx-tls"} 0`,
		`kube_secret_gateway_agent_last_successful_sync_timestamp_seconds{bundle="nginx-tls"}`,
		`kube_secret_gateway_agent_sync_duration_seconds_count{bundle="nginx-tls"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics do not contain %q\n%s", want, body)
		}
	}
}

func TestConfiguredBundlesExistBeforeFirstSync(t *testing.T) {
	m, err := metrics.New([]config.Bundle{{Name: "nginx-tls"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := rec.Body.String(); !strings.Contains(got,
		`kube_secret_gateway_agent_bundle_healthy{bundle="nginx-tls"} 0`) {
		t.Fatalf("initial bundle series missing:\n%s", got)
	}
}
