package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kube-secret-gateway/internal/testcerts"
)

// TestEndToEnd runs the real binary wiring against a fake Kubernetes API
// server speaking the list/watch protocol over HTTP, through client-go: once
// with plain HTTP, and once with TLS on the Secrets listener and
// authentication on /metrics.
func TestEndToEnd(t *testing.T) {
	t.Run("plain", func(t *testing.T) { testEndToEnd(t, false) })
	t.Run("tls and metrics auth", func(t *testing.T) { testEndToEnd(t, true) })
}

func testEndToEnd(t *testing.T, secure bool) {
	kube := newFakeKube(t)
	kube.set("certificates", "my-cert", map[string][]byte{"tls.crt": []byte("CERT-V1"), "tls.key": []byte("KEY-MATERIAL")})
	kube.set("certificate-auth", "fetcher", map[string][]byte{"username": []byte("fetcher"), "password": []byte("e2e-password")})
	kube.set("monitoring", "scrape-credentials", map[string][]byte{"username": []byte("prometheus"), "password": []byte("scrape-password")})
	apiServer := httptest.NewServer(kube)
	t.Cleanup(apiServer.Close)

	dir := t.TempDir()
	kubeconfig := writeKubeconfig(t, dir, apiServer.URL)

	addr, metricsAddr := freeAddress(t), freeAddress(t)
	scheme, client := "http", &http.Client{}
	var serverExtra, metricsExtra string
	if secure {
		ca := testcerts.NewAuthority(t)
		certPEM, keyPEM, _ := ca.Issue(t, "127.0.0.1")
		certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		writeFile(t, certFile, string(certPEM))
		writeFile(t, keyFile, string(keyPEM))
		serverExtra = fmt.Sprintf("  tls: {certFile: %q, keyFile: %q}\n", certFile, keyFile)
		metricsExtra = "  auth: {type: basicAuth, secretRef: {namespace: monitoring, name: scrape-credentials}}\n"
		scheme = "https"
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool()}}}
	}
	configPath := filepath.Join(dir, "config.yaml")
	writeFile(t, configPath, fmt.Sprintf(`
server:
  listenAddress: %q
%smetrics:
  listenAddress: %q
%skubernetes:
  defaultNamespace: certificates
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [127.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: fetcher}}
    excludeKeys: [tls.key]
  - name: later
    secretRef: {name: created-later}
    allowedCidrs: [127.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: fetcher}}
    includeKeys: [tls.crt]
`, addr, serverExtra, metricsAddr, metricsExtra))

	ctx, cancel := context.WithCancel(context.Background())
	logs := &lockedBuffer{}
	exitCode := -1
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		exitCode = run(ctx, []string{"-config", configPath, "-kubeconfig", kubeconfig, "-log-level", "debug"}, logs)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
		}
	})

	do := func(c *http.Client, url string, setup func(*http.Request)) (int, string, error) {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		if setup != nil {
			setup(req)
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	get := func(path string) (int, string) {
		code, b, err := do(client, scheme+"://"+addr+path, func(r *http.Request) { r.SetBasicAuth("fetcher", "e2e-password") })
		if err != nil {
			t.Fatal(err)
		}
		return code, b
	}
	scrape := func(path string, withCredentials bool) (int, string) {
		code, b, _ := do(http.DefaultClient, "http://"+metricsAddr+path, func(r *http.Request) {
			if withCredentials {
				r.SetBasicAuth("prometheus", "scrape-password")
			}
		})
		return code, b
	}

	eventually(t, "gateway ready", func() bool { c, _ := scrape("/readyz", false); return c == http.StatusOK })
	kube.waitWatching(t, "certificates", "my-cert")
	kube.waitWatching(t, "certificates", "created-later")

	if code, body := get("/secrets/my-cert/tls.crt"); code != 200 || body != "CERT-V1" {
		t.Fatalf("initial GET = %d %q", code, body)
	}
	if code, _ := get("/secrets/my-cert/tls.key"); code != 404 {
		t.Fatalf("excluded key = %d", code)
	}
	if code, _ := get("/secrets/later/tls.crt"); code != 503 {
		t.Fatalf("not yet created Secret = %d", code)
	}
	// Probes and metrics live only on the metrics listener.
	for _, p := range []string{"/readyz", "/healthz", "/metrics"} {
		if code, _ := get(p); code != 404 {
			t.Fatalf("%s on the Secrets listener = %d, want 404", p, code)
		}
	}
	if secure {
		// Plain HTTP to the TLS listener is refused by net/http.
		if code, _, err := do(http.DefaultClient, "http://"+addr+"/secrets/my-cert/tls.crt", nil); err == nil && code != http.StatusBadRequest {
			t.Fatalf("plain HTTP to the TLS listener = %d", code)
		}
	}

	// Watch events flow through client-go into the cache.
	kube.set("certificates", "my-cert", map[string][]byte{"tls.crt": []byte("CERT-V2")})
	eventually(t, "modified value served", func() bool { _, b := get("/secrets/my-cert/tls.crt"); return b == "CERT-V2" })
	kube.remove("certificates", "my-cert")
	eventually(t, "deleted Secret unavailable", func() bool { c, _ := get("/secrets/my-cert/tls.crt"); return c == 503 })
	kube.set("certificates", "created-later", map[string][]byte{"tls.crt": []byte("LATE")})
	eventually(t, "created Secret served", func() bool { _, b := get("/secrets/later/tls.crt"); return b == "LATE" })

	// Metrics reflect state without any request for the Secret.
	if secure {
		if code, _ := scrape("/metrics", false); code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated scrape = %d, want 401", code)
		}
	}
	code, metricsBody := scrape("/metrics", secure)
	if code != http.StatusOK {
		t.Fatalf("scrape = %d", code)
	}
	wantMetrics := []string{
		`kube_secret_gateway_source_secret_present{export="my-cert",namespace="certificates",secret="my-cert"} 0`,
		`kube_secret_gateway_source_secret_present{export="later",namespace="certificates",secret="created-later"} 1`,
		`kube_secret_gateway_watch_connected{namespace="certificate-auth",secret="fetcher"} 1`,
	}
	if secure {
		wantMetrics = append(wantMetrics, `kube_secret_gateway_watch_connected{namespace="monitoring",secret="scrape-credentials"} 1`)
	}
	for _, want := range wantMetrics {
		if !strings.Contains(metricsBody, want) {
			t.Errorf("metrics lack %q", want)
		}
	}

	// A dropped watch is recovered with a relist and a new watch.
	watchesBefore := kube.count("watch", "certificates", "created-later")
	kube.dropWatches("certificates", "created-later")
	eventually(t, "watch re-established", func() bool {
		return kube.count("watch", "certificates", "created-later") > watchesBefore && kube.watching("certificates", "created-later")
	})

	cancel()
	select {
	case <-exited:
		if exitCode != 0 {
			t.Fatalf("exit code %d; logs:\n%s", exitCode, logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not shut down")
	}

	// Every request was an exact-name request in an explicit namespace.
	for _, r := range kube.requestLog() {
		if strings.Contains(r, "must-not-be-used") {
			t.Errorf("request used the kubeconfig namespace: %s", r)
		}
		if !strings.HasPrefix(r, "/api/v1/namespaces/certificates/") &&
			!strings.HasPrefix(r, "/api/v1/namespaces/certificate-auth/") &&
			!(secure && strings.HasPrefix(r, "/api/v1/namespaces/monitoring/")) {
			t.Errorf("unexpected request %s", r)
		}
	}
	if v := kube.violations(); len(v) > 0 {
		t.Errorf("unrestricted list/watch requests: %v", v)
	}
	for _, s := range []string{"CERT-V1", "CERT-V2", "KEY-MATERIAL", "e2e-password", "scrape-password", "LATE"} {
		if strings.Contains(logs.String(), s) {
			t.Errorf("logs contain %q", s)
		}
	}
}

func TestMetricsAuthSecretRequiredAtStartup(t *testing.T) {
	for name, tc := range map[string]struct {
		data map[string][]byte
		want string
	}{
		"missing":   {nil, "the Secret does not exist"},
		"malformed": {map[string][]byte{"username": []byte("prometheus")}, `no non-empty \"password\" key`},
	} {
		t.Run(name, func(t *testing.T) {
			kube := newFakeKube(t)
			if tc.data != nil {
				kube.set("monitoring", "scrape-credentials", tc.data)
			}
			apiServer := httptest.NewServer(kube)
			t.Cleanup(apiServer.Close)
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			writeFile(t, configPath, fmt.Sprintf(`
server: {listenAddress: %q}
metrics:
  listenAddress: %q
  auth: {type: basicAuth, secretRef: {namespace: monitoring, name: scrape-credentials}}
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [127.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: fetcher}}
`, freeAddress(t), freeAddress(t)))

			logs := &lockedBuffer{}
			args := []string{"-config", configPath, "-kubeconfig", writeKubeconfig(t, dir, apiServer.URL)}
			if code := run(context.Background(), args, logs); code != 1 {
				t.Fatalf("exit code %d, want 1; logs:\n%s", code, logs.String())
			}
			if !strings.Contains(logs.String(), "metrics authentication is not usable") || !strings.Contains(logs.String(), tc.want) {
				t.Fatalf("logs lack the reason %q:\n%s", tc.want, logs.String())
			}
			if strings.Contains(logs.String(), `"msg":"listening"`) {
				t.Fatal("the gateway served before verifying the metrics credentials")
			}
		})
	}
}

func TestInvalidConfigurationFailsBeforeListening(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	writeFile(t, configPath, "secrets:\n  - secretRef: {name: x}\n")
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", configPath}, &stderr); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cannot load configuration") || !strings.Contains(stderr.String(), "allowedCidrs") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestMissingConfigurationFile(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", filepath.Join(t.TempDir(), "nope.yaml")}, &stderr); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
}

func TestInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-no-such-flag"},
		{"-log-level", "loud"},
		{"-log-format", "xml"},
		{"extra-argument"},
	} {
		var stderr bytes.Buffer
		if code := run(context.Background(), args, &stderr); code != 2 {
			t.Errorf("%v: exit code %d, want 2", args, code)
		}
	}
}

// fakeKube is a minimal Kubernetes API server for Secrets. It rejects list
// and watch requests that are not restricted to one name.
type fakeKube struct {
	t        *testing.T
	mu       sync.Mutex
	rv       int
	secrets  map[string]*corev1.Secret
	watchers map[string][]chan []byte
	requests []string
	calls    map[string]int
	bad      []string
}

func newFakeKube(t *testing.T) *fakeKube {
	return &fakeKube{
		t:        t,
		rv:       1000,
		secrets:  make(map[string]*corev1.Secret),
		watchers: make(map[string][]chan []byte),
		calls:    make(map[string]int),
	}
}

func (f *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.String())
	f.mu.Unlock()

	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) < 2 || len(parts) > 3 || parts[1] != "secrets" || r.Method != http.MethodGet {
		http.Error(w, "unexpected request", http.StatusNotFound)
		return
	}
	ns := parts[0]
	if len(parts) == 3 {
		f.get(w, ns, parts[2])
		return
	}
	name, ok := strings.CutPrefix(r.URL.Query().Get("fieldSelector"), "metadata.name=")
	if !ok || name == "" {
		f.mu.Lock()
		f.bad = append(f.bad, r.URL.String())
		f.mu.Unlock()
		http.Error(w, "unrestricted request", http.StatusForbidden)
		return
	}
	if r.URL.Query().Get("watch") == "true" {
		f.watch(w, r, ns, name)
		return
	}
	f.list(w, ns, name)
}

func key(ns, name string) string { return ns + "/" + name }

func (f *fakeKube) get(w http.ResponseWriter, ns, name string) {
	f.mu.Lock()
	f.calls["get "+key(ns, name)]++
	s, ok := f.secrets[key(ns, name)]
	f.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, &metav1.Status{
			TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
			Status:   metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound,
		})
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (f *fakeKube) list(w http.ResponseWriter, ns, name string) {
	f.mu.Lock()
	f.calls["list "+key(ns, name)]++
	list := &corev1.SecretList{
		TypeMeta: metav1.TypeMeta{Kind: "SecretList", APIVersion: "v1"},
		ListMeta: metav1.ListMeta{ResourceVersion: strconv.Itoa(f.rv)},
	}
	if s, ok := f.secrets[key(ns, name)]; ok {
		list.Items = append(list.Items, *s.DeepCopy())
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, list)
}

func (f *fakeKube) watch(w http.ResponseWriter, r *http.Request, ns, name string) {
	ch := make(chan []byte, 16)
	k := key(ns, name)
	f.mu.Lock()
	f.calls["watch "+k]++
	f.watchers[k] = append(f.watchers[k], ch)
	f.mu.Unlock()
	defer f.unregister(k, ch)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_, _ = w.Write(append(ev, '\n'))
			w.(http.Flusher).Flush()
		}
	}
}

func (f *fakeKube) unregister(k string, ch chan []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.watchers[k]
	for i, c := range list {
		if c == ch {
			f.watchers[k] = append(list[:i], list[i+1:]...)
			return
		}
	}
}

func (f *fakeKube) set(ns, name string, data map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	evType := "MODIFIED"
	if _, ok := f.secrets[key(ns, name)]; !ok {
		evType = "ADDED"
	}
	s := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, ResourceVersion: strconv.Itoa(f.rv)},
		Data:       data,
	}
	f.secrets[key(ns, name)] = s
	f.broadcast(key(ns, name), evType, s)
}

func (f *fakeKube) remove(ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[key(ns, name)]
	if !ok {
		return
	}
	delete(f.secrets, key(ns, name))
	f.rv++
	s.ResourceVersion = strconv.Itoa(f.rv)
	f.broadcast(key(ns, name), "DELETED", s)
}

// broadcast must be called with f.mu held.
func (f *fakeKube) broadcast(k, evType string, s *corev1.Secret) {
	ev, err := json.Marshal(map[string]any{"type": evType, "object": s})
	if err != nil {
		f.t.Error(err)
		return
	}
	for _, ch := range f.watchers[k] {
		ch <- ev
	}
}

func (f *fakeKube) dropWatches(ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.watchers[key(ns, name)] {
		close(ch)
	}
	delete(f.watchers, key(ns, name))
}

func (f *fakeKube) watching(ns, name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.watchers[key(ns, name)]) > 0
}

func (f *fakeKube) waitWatching(t *testing.T, ns, name string) {
	t.Helper()
	eventually(t, "watch on "+key(ns, name), func() bool { return f.watching(ns, name) })
}

func (f *fakeKube) count(verb, ns, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[verb+" "+key(ns, name)]
}

func (f *fakeKube) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fakeKube) violations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bad...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeKubeconfig points the client at the fake API server. Its context
// namespace must never be used by the gateway.
func writeKubeconfig(t *testing.T, dir, server string) string {
	t.Helper()
	path := filepath.Join(dir, "kubeconfig")
	writeFile(t, path, fmt.Sprintf(`
apiVersion: v1
kind: Config
clusters:
  - name: fake
    cluster: {server: %q}
users:
  - name: fake
    user: {token: test-token}
contexts:
  - name: fake
    context: {cluster: fake, user: fake, namespace: must-not-be-used}
current-context: fake
`, server))
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
