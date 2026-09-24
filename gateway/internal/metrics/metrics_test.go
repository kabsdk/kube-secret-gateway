package metrics_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	"kube-secret-gateway/internal/config"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/kubernetes/kubetest"
	"kube-secret-gateway/internal/metrics"
	"kube-secret-gateway/internal/resources"
)

const testConfig = `
kubernetes:
  defaultNamespace: certificates
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.0/8]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: my-cert-fetcher-credentials}}
  - name: matrix-prod
    secretRef: {namespace: matrix-prod, name: matrix-cert}
    allowedCidrs: [10.0.0.0/8]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: my-cert-fetcher-credentials}}
    includeKeys: [tls.crt, tls.key]
  - name: my-cert-public
    secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.0/8]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: my-cert-fetcher-credentials}}
    excludeKeys: [tls.key]
`

var (
	certRef   = exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}
	matrixRef = exposure.SecretRef{Namespace: "matrix-prod", Name: "matrix-cert"}
	authRef   = exposure.SecretRef{Namespace: "certificate-auth", Name: "my-cert-fetcher-credentials"}
)

type fixture struct {
	api *kubetest.FakeAPI
	mgr *resources.Manager
	m   *metrics.Metrics
	reg *prometheus.Registry
}

func newFixture(t *testing.T, seed func(api *kubetest.FakeAPI)) *fixture {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	api := kubetest.New()
	if seed != nil {
		seed(api)
	}
	mgr := resources.NewManager(api, exposure.ReferencedSecrets(cfg.Exposures), resources.Options{
		ReconcileInterval:   time.Hour,
		WatchTimeout:        time.Hour,
		InitialBackoff:      time.Millisecond,
		MaxBackoff:          5 * time.Millisecond,
		StableWatchDuration: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	mgr.Start(ctx)
	t.Cleanup(func() { cancel(); mgr.Wait() })
	if err := mgr.WaitInitialized(ctx); err != nil {
		t.Fatal(err)
	}
	m, err := metrics.New(cfg.Exposures, mgr)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{api: api, mgr: mgr, m: m, reg: m.Registry()}
}

func seedAll(api *kubetest.FakeAPI) {
	api.Apply(certRef, map[string][]byte{"tls.crt": []byte("C"), "tls.key": []byte("K")})
	api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("C"), "tls.key": []byte("K")})
	api.Apply(authRef, map[string][]byte{"username": []byte("u"), "password": []byte("p")})
}

// value returns the value of the series name{labels}, and whether it exists.
func value(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					continue series
				}
			}
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue(), true
			}
			return m.GetCounter().GetValue(), true
		}
	}
	return 0, false
}

func expectValue(t *testing.T, f *fixture, name string, labels map[string]string, want float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, ok := value(t, f.reg, name, labels)
		if ok && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s%v = %v (exists=%v), want %v", name, labels, got, ok, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func exposureLabels(name string, ref exposure.SecretRef) map[string]string {
	return map[string]string{"exposure": name, "namespace": ref.Namespace, "secret": ref.Name}
}

func refLabels(ref exposure.SecretRef) map[string]string {
	return map[string]string{"namespace": ref.Namespace, "secret": ref.Name}
}

func TestSourceSecretPresenceTransitions(t *testing.T) {
	f := newFixture(t, seedAll)
	const name = "kube_secret_gateway_source_secret_present"
	labels := exposureLabels("my-cert", certRef)

	expectValue(t, f, name, labels, 1)
	f.api.Delete(certRef)
	expectValue(t, f, name, labels, 0)
	expectValue(t, f, name, exposureLabels("my-cert-public", certRef), 0)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", map[string]string{"exposure": "my-cert"}, 0)
	f.api.Apply(certRef, map[string][]byte{"tls.crt": []byte("C2")})
	expectValue(t, f, name, labels, 1)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", map[string]string{"exposure": "my-cert"}, 1)
}

func TestMissingAtStartupIsReportedWithoutRequests(t *testing.T) {
	f := newFixture(t, nil)
	expectValue(t, f, "kube_secret_gateway_source_secret_present", exposureLabels("my-cert", certRef), 0)
	expectValue(t, f, "kube_secret_gateway_auth_secret_present", exposureLabels("my-cert", authRef), 0)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", map[string]string{"exposure": "matrix-prod"}, 0)
}

func TestAuthSecretPresenceAndValidity(t *testing.T) {
	f := newFixture(t, func(api *kubetest.FakeAPI) {
		api.Apply(certRef, map[string][]byte{"tls.crt": []byte("C")})
	})
	present, valid := "kube_secret_gateway_auth_secret_present", "kube_secret_gateway_auth_secret_valid"
	labels := exposureLabels("my-cert", authRef)

	expectValue(t, f, present, labels, 0)
	expectValue(t, f, valid, labels, 0)

	f.api.Apply(authRef, map[string][]byte{"username": []byte("u")}) // password missing
	expectValue(t, f, present, labels, 1)
	expectValue(t, f, valid, labels, 0)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", map[string]string{"exposure": "my-cert"}, 0)

	f.api.Apply(authRef, map[string][]byte{"password": []byte("p")}) // username missing
	expectValue(t, f, valid, labels, 0)

	f.api.Apply(authRef, map[string][]byte{"username": []byte("u"), "password": []byte("p")})
	expectValue(t, f, valid, labels, 1)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", map[string]string{"exposure": "my-cert"}, 1)

	f.api.Delete(authRef)
	expectValue(t, f, present, labels, 0)
	expectValue(t, f, valid, labels, 0)

	f.api.Apply(authRef, map[string][]byte{"username": []byte("u"), "password": []byte("p")})
	expectValue(t, f, present, labels, 1)
}

func TestExpectedKeyPresence(t *testing.T) {
	f := newFixture(t, seedAll)
	const name = "kube_secret_gateway_expected_key_present"
	crt := map[string]string{"exposure": "matrix-prod", "key": "tls.crt"}
	key := map[string]string{"exposure": "matrix-prod", "key": "tls.key"}
	healthy := map[string]string{"exposure": "matrix-prod"}

	expectValue(t, f, name, crt, 1)
	expectValue(t, f, name, key, 1)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", healthy, 1)

	f.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("C")})
	expectValue(t, f, name, key, 0)
	expectValue(t, f, name, crt, 1)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", healthy, 0)

	f.api.Delete(matrixRef)
	expectValue(t, f, name, crt, 0)

	f.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("C"), "tls.key": []byte("K")})
	expectValue(t, f, name, key, 1)
	expectValue(t, f, "kube_secret_gateway_exposure_healthy", healthy, 1)

	// Only includeKeys produce expected-key series.
	if _, ok := value(t, f.reg, name, map[string]string{"exposure": "my-cert", "key": "tls.crt"}); ok {
		t.Fatal("expected_key_present emitted for an exposure without includeKeys")
	}
}

func TestWatchConnectionAndErrors(t *testing.T) {
	f := newFixture(t, seedAll)
	connected := "kube_secret_gateway_watch_connected"
	errorsTotal := "kube_secret_gateway_watch_errors_total"

	expectValue(t, f, connected, refLabels(certRef), 1)
	expectValue(t, f, errorsTotal, refLabels(certRef), 0)

	f.api.SendEvent(certRef, watch.Event{Type: watch.Error, Object: &metav1.Status{Code: 500, Reason: metav1.StatusReasonInternalError}})
	expectValue(t, f, errorsTotal, refLabels(certRef), 1)
	expectValue(t, f, connected, refLabels(certRef), 1)

	f.api.SetError(kubetest.Watch, certRef, errors.New("refused"))
	f.api.CloseWatches(certRef)
	eventuallyAtLeast(t, f, errorsTotal, refLabels(certRef), 2)
	expectValue(t, f, connected, refLabels(certRef), 0)
	f.api.SetError(kubetest.Watch, certRef, nil)
	expectValue(t, f, connected, refLabels(certRef), 1)

	if v, _ := value(t, f.reg, errorsTotal, refLabels(authRef)); v != 0 {
		t.Fatalf("errors leaked to another Secret's series: %v", v)
	}
}

func TestSyncMetrics(t *testing.T) {
	before := float64(time.Now().Add(-time.Second).Unix())
	f := newFixture(t, seedAll)
	ts, ok := value(t, f.reg, "kube_secret_gateway_last_successful_sync_timestamp_seconds", refLabels(certRef))
	if !ok || ts < before || ts > float64(time.Now().Unix()+1) {
		t.Fatalf("last sync timestamp = %v (exists=%v)", ts, ok)
	}
	expectValue(t, f, "kube_secret_gateway_sync_errors_total", refLabels(certRef), 0)

	f.api.SetError(kubetest.List, certRef, errors.New("down"))
	f.api.CloseWatches(certRef)
	eventuallyAtLeast(t, f, "kube_secret_gateway_sync_errors_total", refLabels(certRef), 1)
}

func eventuallyAtLeast(t *testing.T, f *fixture, name string, labels map[string]string, min float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if v, ok := value(t, f.reg, name, labels); ok && v >= min {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s%v never reached %v", name, labels, min)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSharedSecretHasOneResourceSeries(t *testing.T) {
	f := newFixture(t, seedAll)
	refs := []exposure.SecretRef{certRef, matrixRef, authRef}
	for _, ref := range refs {
		// WaitInitialized guarantees that the initial list completed, but a
		// watcher may not have been scheduled yet. Wait for the observable
		// connected state before asserting how many watches were created.
		expectValue(t, f, "kube_secret_gateway_watch_connected", refLabels(ref), 1)
	}

	// my-cert (shared by two exposures), matrix-cert, and the auth Secret
	// shared by all three.
	if n := seriesCount(t, f.reg, "kube_secret_gateway_watch_connected"); n != 3 {
		t.Fatalf("got %d watch_connected series, want 3", n)
	}
	for _, ref := range refs {
		if n := f.api.CallCount(kubetest.Watch, ref); n != 1 {
			t.Fatalf("%s watched %d times, want once", ref, n)
		}
	}
}

func TestRequestLabelsAreBounded(t *testing.T) {
	f := newFixture(t, seedAll)
	f.m.ObserveRequest("my-cert", http.StatusOK, "served")
	f.m.ObserveRequest("my-cert", http.StatusOK, "served")
	f.m.ObserveRequest("my-cert", http.StatusNotFound, "client_not_allowed")
	f.m.ObserveRequest("", http.StatusNotFound, "no_route")
	for i := range 200 {
		f.m.ObserveRequest(fmt.Sprintf("attacker-%d", i), http.StatusNotFound, "unknown_exposure")
	}
	f.m.ObserveRequest("my-cert", 99999, "internal_error")

	counter := "kube_secret_gateway_http_requests_total"
	expectValue(t, f, counter, map[string]string{"exposure": "my-cert", "status": "200", "reason": "served"}, 2)
	expectValue(t, f, counter, map[string]string{"exposure": "my-cert", "status": "404", "reason": "client_not_allowed"}, 1)
	expectValue(t, f, counter, map[string]string{"exposure": metrics.UnknownExposure, "status": "404", "reason": "no_route"}, 1)
	expectValue(t, f, counter, map[string]string{"exposure": metrics.UnknownExposure, "status": "404", "reason": "unknown_exposure"}, 200)
	expectValue(t, f, counter, map[string]string{"exposure": "my-cert", "status": "other", "reason": "internal_error"}, 1)
	if n := seriesCount(t, f.reg, counter); n != 5 {
		t.Fatalf("got %d request series, want 5", n)
	}
}

func seriesCount(t *testing.T, reg *prometheus.Registry, name string) int {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() == name {
			return len(mf.GetMetric())
		}
	}
	return 0
}

func TestMetricsLint(t *testing.T) {
	f := newFixture(t, seedAll)
	problems, err := testutil.GatherAndLint(f.reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		if strings.HasPrefix(p.Metric, "kube_secret_gateway_") {
			t.Errorf("lint: %s: %s", p.Metric, p.Text)
		}
	}
}

func TestHandlerServesExposition(t *testing.T) {
	f := newFixture(t, seedAll)
	rv := f.api.Apply(authRef, map[string][]byte{"username": []byte("USER-VALUE-4711"), "password": []byte("PASSWORD-VALUE-4711")})
	waitVersion(t, f.mgr, authRef, rv)
	rec := httptest.NewRecorder()
	f.m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`kube_secret_gateway_source_secret_present{exposure="my-cert",namespace="certificates",secret="my-cert"} 1`,
		`kube_secret_gateway_auth_secret_present{exposure="my-cert",namespace="certificate-auth",secret="my-cert-fetcher-credentials"} 1`,
		`kube_secret_gateway_expected_key_present{exposure="matrix-prod",key="tls.crt"} 1`,
		`kube_secret_gateway_watch_connected{namespace="certificates",secret="my-cert"} 1`,
		`kube_secret_gateway_watch_errors_total{namespace="certificates",secret="my-cert"} 0`,
		`kube_secret_gateway_last_successful_sync_timestamp_seconds{namespace="certificates",secret="my-cert"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition lacks %q", want)
		}
	}
	if strings.Contains(body, "VALUE-4711") {
		t.Error("exposition leaks Secret data")
	}
}

func waitVersion(t *testing.T, m *resources.Manager, ref exposure.SecretRef, rv string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for m.Secret(ref).ResourceVersion != rv {
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached resourceVersion %s", ref, rv)
		}
		time.Sleep(time.Millisecond)
	}
}
