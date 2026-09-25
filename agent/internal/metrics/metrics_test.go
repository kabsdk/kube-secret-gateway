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

func TestMetricsDescribeExposureState(t *testing.T) {
	m, err := metrics.New([]config.Exposure{{Name: "my-cert"}}, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	// One changed success, one unchanged success and one error exercise every
	// state transition. The last result determines the health gauge.
	m.ObserveSync("my-cert", true, nil, 100*time.Millisecond)
	m.ObserveSync("my-cert", false, nil, 50*time.Millisecond)
	m.ObserveSync("my-cert", false, errors.New("gateway unavailable"), 25*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`kube_secret_gateway_agent_build_info{version="test-version"} 1`,
		`kube_secret_gateway_agent_sync_attempts_total{exposure="my-cert"} 3`,
		`kube_secret_gateway_agent_sync_errors_total{exposure="my-cert"} 1`,
		`kube_secret_gateway_agent_changes_total{exposure="my-cert"} 1`,
		`kube_secret_gateway_agent_exposure_healthy{exposure="my-cert"} 0`,
		`kube_secret_gateway_agent_last_successful_sync_timestamp_seconds{exposure="my-cert"}`,
		`kube_secret_gateway_agent_sync_duration_seconds_count{exposure="my-cert"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics do not contain %q\n%s", want, body)
		}
	}
}

func TestConfiguredExposuresExistBeforeFirstSync(t *testing.T) {
	m, err := metrics.New([]config.Exposure{{Name: "my-cert"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := rec.Body.String(); !strings.Contains(got,
		`kube_secret_gateway_agent_exposure_healthy{exposure="my-cert"} 0`) {
		t.Fatalf("initial exposure series missing:\n%s", got)
	}
}
