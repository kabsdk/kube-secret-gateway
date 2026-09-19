package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"kube-secret-gateway/internal/clientip"
	"kube-secret-gateway/internal/config"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/kubernetes/kubetest"
	"kube-secret-gateway/internal/metrics"
	"kube-secret-gateway/internal/resources"
	"kube-secret-gateway/internal/server"
)

const testConfig = `
server:
  trustedProxies: [10.42.0.0/16]
kubernetes:
  defaultNamespace: certificates
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.10.30.40/32, "2001:db8::/64", 127.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: fetcher}}

  - name: matrix-prod
    secretRef: {namespace: matrix-prod, name: matrix-cert}
    allowedCidrs: [10.10.30.40/32]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: fetcher}}
    includeKeys: [tls.crt, tls.key]

  - name: public-only
    secretRef: {name: my-cert}
    allowedCidrs: [10.10.30.40/32]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: fetcher}}
    excludeKeys: [tls.key]

  - name: pending
    secretRef: {name: not-created-yet}
    allowedCidrs: [10.10.30.40/32]
    auth: {type: basicAuth, secretRef: {namespace: certificate-auth, name: fetcher}}

  - name: self-contained
    secretRef: {namespace: bundles, name: bundle}
    allowedCidrs: [10.10.30.40/32]
    auth: {type: basicAuth, secretRef: {namespace: bundles, name: bundle}}
    includeKeys: [ca.crt]
`

const (
	username = "fetcher"
	password = "correct horse battery staple"
	certPEM  = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	keyPEM   = "-----BEGIN PRIVATE KEY-----\nPRIVATE-KEY-MATERIAL\n-----END PRIVATE KEY-----\n"
)

var (
	certRef   = exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}
	matrixRef = exposure.SecretRef{Namespace: "matrix-prod", Name: "matrix-cert"}
	authRef   = exposure.SecretRef{Namespace: "certificate-auth", Name: "fetcher"}
	bundleRef = exposure.SecretRef{Namespace: "bundles", Name: "bundle"}
)

type harness struct {
	t       *testing.T
	api     *kubetest.FakeAPI
	mgr     *resources.Manager
	metrics *metrics.Metrics
	source  *countingSource
	handler http.Handler
	logs    *lockedBuffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, api: kubetest.New(), logs: &lockedBuffer{}}
	h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte(certPEM), "tls.key": []byte(keyPEM), "ca.crt": []byte("CA")})
	h.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("MATRIX-CRT"), "tls.key": []byte("MATRIX-KEY")})
	h.api.Apply(authRef, credentials(username, password))
	bundle := credentials("bundle-user", "bundle-pass")
	bundle["ca.crt"] = []byte("BUNDLE-CA")
	h.api.Apply(bundleRef, bundle)

	h.mgr = resources.NewManager(h.api, exposure.ReferencedSecrets(cfg.Exposures), resources.Options{
		ReconcileInterval:   time.Hour,
		WatchTimeout:        time.Hour,
		InitialBackoff:      time.Millisecond,
		MaxBackoff:          5 * time.Millisecond,
		StableWatchDuration: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	h.mgr.Start(ctx)
	t.Cleanup(func() { cancel(); h.mgr.Wait() })
	if err := h.mgr.WaitInitialized(ctx); err != nil {
		t.Fatal(err)
	}

	h.metrics, err = metrics.New(cfg.Exposures, h.mgr)
	if err != nil {
		t.Fatal(err)
	}
	h.source = &countingSource{inner: h.mgr}
	logger := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.handler, err = server.New(server.Options{
		Exposures: cfg.Exposures,
		Secrets:   h.source,
		ClientIP:  clientip.NewResolver(cfg.Server.TrustedProxies),
		Observer:  h.metrics,
		Logger:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func credentials(u, p string) map[string][]byte {
	return map[string][]byte{"username": []byte(u), "password": []byte(p)}
}

type reqOption func(r *http.Request)

func from(remoteAddr string) reqOption { return func(r *http.Request) { r.RemoteAddr = remoteAddr } }
func withAuth(u, p string) reqOption   { return func(r *http.Request) { r.SetBasicAuth(u, p) } }
func withoutAuth() reqOption           { return func(r *http.Request) { r.Header.Del("Authorization") } }
func withHeader(k, v string) reqOption {
	return func(r *http.Request) { r.Header.Add(k, v) }
}
func withMethod(m string) reqOption { return func(r *http.Request) { r.Method = m } }

// do serves one request from an allowed client with valid credentials,
// unless options say otherwise.
func (h *harness) do(target string, opts ...reqOption) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = "10.10.30.40:52100"
	r.SetBasicAuth(username, password)
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func (h *harness) waitVersion(ref exposure.SecretRef, rv string) {
	h.t.Helper()
	h.eventually("resourceVersion "+rv+" of "+ref.String(), func() bool { return h.mgr.Secret(ref).ResourceVersion == rv })
}

func (h *harness) waitAbsent(ref exposure.SecretRef) {
	h.t.Helper()
	h.eventually(ref.String()+" absent", func() bool { return !h.mgr.Secret(ref).Present })
}

func (h *harness) eventually(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, want, rec.Body.String())
	}
}

// etag is the expected ETag of value served from ref's current incarnation.
func (h *harness) etag(ref exposure.SecretRef, value string) string {
	return server.ETag([]byte(value), h.mgr.Secret(ref).UID)
}

func TestConfiguredExposureServesRawValue(t *testing.T) {
	h := newHarness(t)
	rec := h.do("/secrets/my-cert/tls.crt")
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.String() != certPEM {
		t.Fatalf("body = %q", rec.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type":           "application/octet-stream",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"ETag":                   h.etag(certRef, certPEM),
		"Content-Length":         fmt.Sprint(len(certPEM)),
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestAllKeysExposedByDefault(t *testing.T) {
	h := newHarness(t)
	for key, want := range map[string]string{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": "CA"} {
		rec := h.do("/secrets/my-cert/" + key)
		expectStatus(t, rec, http.StatusOK)
		if rec.Body.String() != want {
			t.Errorf("%s: body = %q", key, rec.Body.String())
		}
	}
}

func TestBinaryValueReturnedUnchanged(t *testing.T) {
	h := newHarness(t)
	binary := []byte{0x00, 0xff, 0xfe, '\r', '\n', 0x80, 0x00, 'P', 'K', 0x03, 0x04}
	rv := h.api.Apply(certRef, map[string][]byte{"keystore.p12": binary, "empty": {}})
	h.waitVersion(certRef, rv)

	rec := h.do("/secrets/my-cert/keystore.p12")
	expectStatus(t, rec, http.StatusOK)
	if !bytes.Equal(rec.Body.Bytes(), binary) {
		t.Fatalf("body = %x, want %x", rec.Body.Bytes(), binary)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	rec = h.do("/secrets/my-cert/empty")
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.Len() != 0 || rec.Header().Get("ETag") != h.etag(certRef, "") {
		t.Fatal("empty value not served as empty body")
	}
}

func TestUnknownExposure(t *testing.T) {
	h := newHarness(t)
	callsBefore := h.api.TotalCalls()
	h.source.reset()

	for _, path := range []string{"/secrets/unknown/tls.crt", "/secrets/not-created-yet/tls.crt", "/secrets/matrix-cert/tls.crt"} {
		rec := h.do(path)
		expectStatus(t, rec, http.StatusNotFound)
		if rec.Body.String() != "Not Found\n" {
			t.Fatalf("body = %q", rec.Body.String())
		}
	}
	if refs := h.source.lookups(); len(refs) != 0 {
		t.Fatalf("unknown exposures caused resource lookups: %v", refs)
	}
	if h.api.TotalCalls() != callsBefore {
		t.Fatal("unknown exposures caused Kubernetes API calls")
	}
}

func TestAllowedAndDeniedClients(t *testing.T) {
	h := newHarness(t)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("10.10.30.40:1")), http.StatusOK)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("[2001:db8::7]:1")), http.StatusOK)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("[::ffff:10.10.30.40]:1")), http.StatusOK)

	h.source.reset()
	for _, addr := range []string{"10.10.30.41:1", "[2001:db9::7]:1", "192.0.2.1:1"} {
		rec := h.do("/secrets/my-cert/tls.crt", from(addr))
		expectStatus(t, rec, http.StatusNotFound)
		if rec.Body.String() != "Not Found\n" {
			t.Fatalf("body = %q", rec.Body.String())
		}
	}
	// A denied client never gets as far as the Secrets.
	if refs := h.source.lookups(); len(refs) != 0 {
		t.Fatalf("denied clients caused lookups: %v", refs)
	}
	// The per-exposure list applies: matrix-prod does not allow IPv6.
	expectStatus(t, h.do("/secrets/matrix-prod/tls.crt", from("[2001:db8::7]:1")), http.StatusNotFound)
}

func TestClientAddressThroughProxies(t *testing.T) {
	h := newHarness(t)
	// Traefik (trusted) forwards the real client.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "10.10.30.40")), http.StatusOK)
	// A proxy chain inside the trusted range.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "10.10.30.40, 10.42.7.7")), http.StatusOK)
	// A client spoofing the header through the trusted proxy: the proxy
	// appended the real address, which is not allowed.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "10.10.30.40, 198.51.100.7")), http.StatusNotFound)
	// A direct, untrusted client spoofing the header.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("198.51.100.7:1"), withHeader("X-Forwarded-For", "10.10.30.40")), http.StatusNotFound)
	// The trusted proxy itself is not an allowed client.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("10.42.0.5:1")), http.StatusNotFound)
	// A broken chain fails closed.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "10.10.30.40, nonsense")), http.StatusNotFound)
}

// TestNothingRevealedBeforeAuthentication checks that the configuration
// cannot be probed: outside an exposure's allow-list it looks exactly like a
// name that does not exist, and key names only matter after authenticating.
func TestNothingRevealedBeforeAuthentication(t *testing.T) {
	h := newHarness(t)
	type response struct {
		status int
		header http.Header
		body   string
	}
	get := func(path string, opts ...reqOption) response {
		rec := h.do(path, opts...)
		return response{rec.Code, rec.Header(), rec.Body.String()}
	}
	outsider := from("198.51.100.7:1")
	unknown := get("/secrets/no-such-exposure/tls.crt", outsider)
	if unknown.status != http.StatusNotFound {
		t.Fatalf("unknown exposure = %d", unknown.status)
	}
	for _, r := range []struct {
		name string
		got  response
	}{
		{"existing exposure from outside the allow-list", get("/secrets/my-cert/tls.crt", outsider)},
		{"existing exposure without credentials", get("/secrets/my-cert/tls.crt", outsider, withoutAuth())},
		{"excluded key from outside", get("/secrets/public-only/tls.key", outsider)},
		{"unknown exposure without credentials", get("/secrets/no-such-exposure/tls.crt", outsider, withoutAuth())},
		{"unresolvable client", get("/secrets/my-cert/tls.crt", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "garbage"))},
	} {
		if r.got.status != unknown.status || r.got.body != unknown.body || !equalHeaders(r.got.header, unknown.header) {
			t.Errorf("%s: %+v differs from an unknown exposure's %+v", r.name, r.got, unknown)
		}
	}

	// On the allow-list but unauthenticated: 401 for every key, whether it
	// is served, excluded or missing.
	for _, path := range []string{"/secrets/public-only/tls.crt", "/secrets/public-only/tls.key", "/secrets/public-only/no-such-key"} {
		for _, opt := range []reqOption{withoutAuth(), withAuth(username, "wrong")} {
			expectStatus(t, h.do(path, opt), http.StatusUnauthorized)
		}
	}
}

func equalHeaders(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if strings.Join(v, ",") != strings.Join(b[k], ",") {
			return false
		}
	}
	return true
}

func TestKeyFilters(t *testing.T) {
	h := newHarness(t)
	// includeKeys
	rec := h.do("/secrets/matrix-prod/tls.key")
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.String() != "MATRIX-KEY" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	rv := h.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("MATRIX-CRT"), "tls.key": []byte("MATRIX-KEY"), "ca.crt": []byte("CA")})
	h.waitVersion(matrixRef, rv)
	expectStatus(t, h.do("/secrets/matrix-prod/ca.crt"), http.StatusNotFound)

	// excludeKeys: the key behaves exactly like one that does not exist.
	expectStatus(t, h.do("/secrets/public-only/tls.crt"), http.StatusOK)
	for _, tc := range []struct {
		opt  reqOption
		want int
	}{
		{withAuth(username, password), http.StatusNotFound},
		{withoutAuth(), http.StatusUnauthorized},
		{from("192.0.2.1:1"), http.StatusNotFound},
	} {
		excluded := h.do("/secrets/public-only/tls.key", tc.opt)
		missing := h.do("/secrets/public-only/no-such-key", tc.opt)
		expectStatus(t, excluded, tc.want)
		expectStatus(t, missing, tc.want)
		if strings.Contains(excluded.Body.String(), "PRIVATE") {
			t.Fatal("excluded key leaked")
		}
	}
	// The same Secret stays fully available through the other exposure.
	expectStatus(t, h.do("/secrets/my-cert/tls.key"), http.StatusOK)
}

func TestMissingKeys(t *testing.T) {
	h := newHarness(t)
	// Ordinary missing key.
	expectStatus(t, h.do("/secrets/my-cert/does-not-exist"), http.StatusNotFound)

	// An explicitly included key that disappears is an operational failure.
	rv := h.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("MATRIX-CRT")})
	h.waitVersion(matrixRef, rv)
	expectStatus(t, h.do("/secrets/matrix-prod/tls.key"), http.StatusServiceUnavailable)
	expectStatus(t, h.do("/secrets/matrix-prod/tls.crt"), http.StatusOK)

	rv = h.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("MATRIX-CRT"), "tls.key": []byte("NEW-KEY")})
	h.waitVersion(matrixRef, rv)
	expectStatus(t, h.do("/secrets/matrix-prod/tls.key"), http.StatusOK)
}

func TestSourceSecretLifecycle(t *testing.T) {
	h := newHarness(t)
	// Configured, but the Secret has never existed.
	rec := h.do("/secrets/pending/tls.crt")
	expectStatus(t, rec, http.StatusServiceUnavailable)
	if rec.Body.String() != "Service Unavailable\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}

	// Deleted while running.
	h.api.Delete(certRef)
	h.waitAbsent(certRef)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusServiceUnavailable)
	expectStatus(t, h.do("/secrets/public-only/tls.crt"), http.StatusServiceUnavailable)
	// A filtered-out key is just a key the exposure does not have: while the
	// Secret is missing it answers like every other key, and like one that
	// never existed.
	expectStatus(t, h.do("/secrets/public-only/tls.key"), http.StatusServiceUnavailable)
	expectStatus(t, h.do("/secrets/public-only/no-such-key"), http.StatusServiceUnavailable)

	// Recreated.
	rv := h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte("RECREATED")})
	h.waitVersion(certRef, rv)
	rec = h.do("/secrets/my-cert/tls.crt")
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.String() != "RECREATED" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestBasicAuthentication(t *testing.T) {
	h := newHarness(t)
	const challenge = `Basic realm="kube-secret-gateway"`

	cases := []struct {
		name string
		opt  reqOption
	}{
		{"missing basic auth", withoutAuth()},
		{"incorrect username", withAuth("someone", password)},
		{"incorrect password", withAuth(username, "wrong")},
		{"both incorrect", withAuth("someone", "wrong")},
		{"non-basic scheme", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+password) }},
	}
	var bodies []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do("/secrets/my-cert/tls.crt", tc.opt)
			expectStatus(t, rec, http.StatusUnauthorized)
			if got := rec.Header().Get("WWW-Authenticate"); got != challenge {
				t.Fatalf("WWW-Authenticate = %q", got)
			}
			bodies = append(bodies, rec.Body.String())
		})
	}
	for _, b := range bodies {
		if b != "Unauthorized\n" {
			t.Fatalf("401 bodies must not reveal what was wrong, got %q", b)
		}
	}
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusOK)
}

func TestAuthSecretLifecycle(t *testing.T) {
	h := newHarness(t)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusOK)

	// Deleted after previously existing: unavailable, with or without credentials.
	h.api.Delete(authRef)
	h.waitAbsent(authRef)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusServiceUnavailable)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", withoutAuth()), http.StatusServiceUnavailable)

	// Recreated.
	rv := h.api.Apply(authRef, credentials(username, password))
	h.waitVersion(authRef, rv)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusOK)

	// Malformed: username key missing, then password key missing.
	rv = h.api.Apply(authRef, map[string][]byte{"password": []byte(password)})
	h.waitVersion(authRef, rv)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusServiceUnavailable)
	rv = h.api.Apply(authRef, map[string][]byte{"username": []byte(username)})
	h.waitVersion(authRef, rv)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusServiceUnavailable)

	// Rotated: new credentials work as soon as the change is observed, old
	// ones stop working.
	rv = h.api.Apply(authRef, credentials("fetcher-v2", "rotated-password"))
	h.waitVersion(authRef, rv)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", withAuth("fetcher-v2", "rotated-password")), http.StatusOK)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusUnauthorized)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", withAuth(username, "rotated-password")), http.StatusUnauthorized)
}

func TestAuthSecretMissingAtStartup(t *testing.T) {
	h := newHarness(t)
	h.api.Delete(authRef)
	h.waitAbsent(authRef)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt"), http.StatusServiceUnavailable)
}

func TestSharedSecretsUseOneWatcher(t *testing.T) {
	h := newHarness(t)
	// my-cert backs two exposures; bundle is both source and auth Secret of
	// self-contained; fetcher authenticates four exposures.
	rec := h.do("/secrets/self-contained/ca.crt", withAuth("bundle-user", "bundle-pass"))
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.String() != "BUNDLE-CA" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	// Credentials in the auth Secret are not exposed by includeKeys.
	expectStatus(t, h.do("/secrets/self-contained/password", withAuth("bundle-user", "bundle-pass")), http.StatusNotFound)

	for _, ref := range []exposure.SecretRef{certRef, authRef, bundleRef} {
		h.eventually("watch "+ref.String(), func() bool { return h.api.OpenWatches(ref) == 1 })
		if n := h.api.CallCount(kubetest.Watch, ref); n != 1 {
			t.Fatalf("%s: %d watches, want 1", ref, n)
		}
	}
}

func TestETag(t *testing.T) {
	h := newHarness(t)
	etag := h.etag(certRef, certPEM)

	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		rec := h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", inm))
		expectStatus(t, rec, http.StatusNotModified)
		if rec.Body.Len() != 0 {
			t.Fatalf("304 with body %q", rec.Body.String())
		}
		if rec.Header().Get("ETag") != etag || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("304 headers = %v", rec.Header())
		}
	}
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", `"sha256:0000"`)), http.StatusOK)

	// A conditional request never bypasses access control.
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", etag), withoutAuth()), http.StatusUnauthorized)

	// Unchanged value under a new resourceVersion keeps the ETag.
	rv := h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte(certPEM), "extra": []byte("x")})
	h.waitVersion(certRef, rv)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", etag)), http.StatusNotModified)

	// A changed value changes the ETag.
	rv = h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte("RENEWED")})
	h.waitVersion(certRef, rv)
	rec := h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", etag))
	expectStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("ETag"); got != h.etag(certRef, "RENEWED") || got == etag {
		t.Fatalf("ETag = %q after change", got)
	}

	// The tag is not a plain hash of the value, so it cannot be used to test
	// guesses offline.
	plain := sha256.Sum256([]byte("RENEWED"))
	if strings.Contains(rec.Header().Get("ETag"), hex.EncodeToString(plain[:])) {
		t.Fatal("ETag is the unkeyed SHA-256 of the value")
	}

	// Recreating the Secret with identical content gives it a new UID, and
	// so a new tag: at most one extra download for clients.
	renewed := rec.Header().Get("ETag")
	h.api.Delete(certRef)
	h.waitAbsent(certRef)
	rv = h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte("RENEWED")})
	h.waitVersion(certRef, rv)
	rec = h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", renewed))
	expectStatus(t, rec, http.StatusOK)
	if rec.Header().Get("ETag") == renewed {
		t.Fatal("ETag unchanged after the Secret was recreated")
	}
}

func TestETagFunction(t *testing.T) {
	tag := server.ETag([]byte("hunter2"), "uid-a")
	if again := server.ETag([]byte("hunter2"), "uid-a"); again != tag {
		t.Fatal("ETag is not deterministic")
	}
	if tag == server.ETag([]byte("hunter2"), "uid-b") {
		t.Fatal("ETag does not depend on the Secret UID")
	}
	if tag == server.ETag([]byte("hunter3"), "uid-a") {
		t.Fatal("ETag does not depend on the value")
	}
	if !strings.HasPrefix(tag, `"hmac-sha256:`) || !strings.HasSuffix(tag, `"`) {
		t.Fatalf("ETag = %s, want a quoted hmac-sha256 tag", tag)
	}
}

// decodeBundle parses a bundle response. json.Unmarshal base64-decodes into
// []byte, which is exactly how the handler encodes the values.
func decodeBundle(t *testing.T, rec *httptest.ResponseRecorder) map[string][]byte {
	t.Helper()
	var got map[string][]byte
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bundle body %q: %v", rec.Body.String(), err)
	}
	return got
}

func TestBundleServesEveryExposedKey(t *testing.T) {
	h := newHarness(t)
	rec := h.do("/bundles/my-cert")
	expectStatus(t, rec, http.StatusOK)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	for _, hdr := range []string{"Cache-Control", "X-Content-Type-Options", "ETag"} {
		if rec.Header().Get(hdr) == "" {
			t.Fatalf("%s missing from bundle response", hdr)
		}
	}
	if got := rec.Header().Get("Content-Length"); got != fmt.Sprint(rec.Body.Len()) {
		t.Fatalf("Content-Length = %q, body is %d bytes", got, rec.Body.Len())
	}

	want := map[string]string{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": "CA"}
	got := decodeBundle(t, rec)
	if len(got) != len(want) {
		t.Fatalf("bundle has %d keys, want %d", len(got), len(want))
	}
	for k, v := range want {
		if string(got[k]) != v {
			t.Fatalf("bundle[%q] = %q, want %q", k, got[k], v)
		}
	}

	// Keys are sorted, so the body is canonical: the ETag depends only on the
	// Secret and the filter, never on map iteration order.
	if !strings.HasPrefix(rec.Body.String(), `{"ca.crt":"`) {
		t.Fatalf("bundle body is not in sorted key order: %q", rec.Body.String())
	}
	for range 5 {
		if again := h.do("/bundles/my-cert"); again.Body.String() != rec.Body.String() {
			t.Fatal("bundle body is not byte-stable across requests")
		}
	}
}

func TestBundleRespectsKeyFilters(t *testing.T) {
	h := newHarness(t)
	// excludeKeys: the excluded key is simply not part of the exposure.
	rec := h.do("/bundles/public-only")
	expectStatus(t, rec, http.StatusOK)
	got := decodeBundle(t, rec)
	if _, ok := got["tls.key"]; ok {
		t.Fatal("excluded key leaked into the bundle")
	}
	if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte(keyPEM))) {
		t.Fatal("excluded value present in the bundle body")
	}
	if string(got["tls.crt"]) != certPEM || string(got["ca.crt"]) != "CA" {
		t.Fatalf("bundle = %v", got)
	}

	// includeKeys: keys outside the list stay invisible even once they exist.
	rv := h.api.Apply(matrixRef, map[string][]byte{
		"tls.crt": []byte("MATRIX-CRT"), "tls.key": []byte("MATRIX-KEY"), "ca.crt": []byte("CA"),
	})
	h.waitVersion(matrixRef, rv)
	got = decodeBundle(t, h.do("/bundles/matrix-prod"))
	if len(got) != 2 || string(got["tls.crt"]) != "MATRIX-CRT" || string(got["tls.key"]) != "MATRIX-KEY" {
		t.Fatalf("includeKeys bundle = %v", got)
	}
}

// TestBundleETagCoversTheWholeSet is the reason the route exists: one
// conditional request tells a client whether any key it installs has changed,
// so it can never assemble a certificate and a key from two versions.
func TestBundleETagCoversTheWholeSet(t *testing.T) {
	h := newHarness(t)
	first := h.do("/bundles/my-cert")
	expectStatus(t, first, http.StatusOK)
	etag := first.Header().Get("ETag")

	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		rec := h.do("/bundles/my-cert", withHeader("If-None-Match", inm))
		expectStatus(t, rec, http.StatusNotModified)
		if rec.Body.Len() != 0 {
			t.Fatalf("304 with body %q", rec.Body.String())
		}
		if rec.Header().Get("ETag") != etag {
			t.Fatalf("304 ETag = %q, want %q", rec.Header().Get("ETag"), etag)
		}
	}

	// A change to any single key changes the tag of the whole bundle.
	rv := h.api.Apply(certRef, map[string][]byte{
		"tls.crt": []byte(certPEM), "tls.key": []byte("ROTATED-KEY"), "ca.crt": []byte("CA"),
	})
	h.waitVersion(certRef, rv)
	rec := h.do("/bundles/my-cert", withHeader("If-None-Match", etag))
	expectStatus(t, rec, http.StatusOK)
	if rec.Header().Get("ETag") == etag {
		t.Fatal("bundle ETag unchanged after one of its keys changed")
	}
	// And the set that comes back is internally consistent: one read of one
	// incarnation of the Secret.
	got := decodeBundle(t, rec)
	if string(got["tls.crt"]) != certPEM || string(got["tls.key"]) != "ROTATED-KEY" {
		t.Fatalf("bundle straddles versions: %v", got)
	}

	// Adding a key the exposure serves also changes the tag.
	before := rec.Header().Get("ETag")
	rv = h.api.Apply(certRef, map[string][]byte{
		"tls.crt": []byte(certPEM), "tls.key": []byte("ROTATED-KEY"), "ca.crt": []byte("CA"), "extra": []byte("x"),
	})
	h.waitVersion(certRef, rv)
	if after := h.do("/bundles/my-cert").Header().Get("ETag"); after == before {
		t.Fatal("bundle ETag unchanged after a key was added")
	}

	// Recreating the Secret changes the UID, and so the tag, exactly once.
	h.api.Delete(certRef)
	h.waitAbsent(certRef)
	rv = h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte(certPEM)})
	h.waitVersion(certRef, rv)
	recreated := h.do("/bundles/my-cert")
	expectStatus(t, recreated, http.StatusOK)
	tag := recreated.Header().Get("ETag")
	if tag == before {
		t.Fatal("bundle ETag unchanged after the Secret was recreated")
	}
	expectStatus(t, h.do("/bundles/my-cert", withHeader("If-None-Match", tag)), http.StatusNotModified)

	// The bundle tag is not the tag of any single value it contains.
	if tag == h.etag(certRef, certPEM) {
		t.Fatal("single-key and bundle ETags collide")
	}
}

// TestBundleBodyIsCanonical pins the wire format. The client repository
// asserts the same literal in its fake gateway (TestCanonicalBody in
// internal/gwtest), and the two share no code, so this pair of assertions is
// what keeps them agreed. Changing the serialisation changes the ETag of every
// bundle and makes every client download once more, so it must be deliberate.
func TestBundleBodyIsCanonical(t *testing.T) {
	const canonicalBody = `{"ca.crt":"Q0E=","tls.crt":"WA=="}`

	h := newHarness(t)
	rv := h.api.Apply(certRef, map[string][]byte{"tls.crt": []byte("X"), "ca.crt": []byte("CA")})
	h.waitVersion(certRef, rv)

	rec := h.do("/bundles/my-cert")
	expectStatus(t, rec, http.StatusOK)
	if got := rec.Body.String(); got != canonicalBody {
		t.Fatalf("bundle body = %s\nwant         %s", got, canonicalBody)
	}
	// The tag is the HMAC of exactly those bytes, keyed with the Secret UID.
	if got, want := rec.Header().Get("ETag"), h.etag(certRef, canonicalBody); got != want {
		t.Fatalf("ETag = %s, want the tag of the canonical body %s", got, want)
	}
}

func TestBundleRequiredKeyMissing(t *testing.T) {
	h := newHarness(t)
	// includeKeys promises tls.key, so losing it is an operational failure
	// for the bundle just as it is for the single key.
	rv := h.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("MATRIX-CRT")})
	h.waitVersion(matrixRef, rv)
	rec := h.do("/bundles/matrix-prod")
	expectStatus(t, rec, http.StatusServiceUnavailable)
	if strings.Contains(rec.Body.String(), "MATRIX") || strings.Contains(rec.Body.String(), "tls") {
		t.Fatalf("503 body leaked: %q", rec.Body.String())
	}
	// A partial bundle is never served.
	if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte("MATRIX-CRT"))) {
		t.Fatal("bundle served the keys it did have")
	}

	rv = h.api.Apply(matrixRef, map[string][]byte{"tls.crt": []byte("MATRIX-CRT"), "tls.key": []byte("NEW")})
	h.waitVersion(matrixRef, rv)
	expectStatus(t, h.do("/bundles/matrix-prod"), http.StatusOK)
}

func TestBundleOfSecretWithNoExposedKeys(t *testing.T) {
	h := newHarness(t)
	rv := h.api.Apply(certRef, map[string][]byte{})
	h.waitVersion(certRef, rv)
	rec := h.do("/bundles/my-cert")
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.String() != "{}" {
		t.Fatalf("empty bundle = %q, want {}", rec.Body.String())
	}
}

func TestBundleAccessControlMatchesSingleKeys(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		what string
		opts []reqOption
		want int
	}{
		{"outside the allow-list", []reqOption{from("192.0.2.1:1")}, http.StatusNotFound},
		{"without credentials", []reqOption{withoutAuth()}, http.StatusUnauthorized},
		{"wrong password", []reqOption{withAuth(username, "nope")}, http.StatusUnauthorized},
	} {
		t.Run(tc.what, func(t *testing.T) {
			rec := h.do("/bundles/my-cert", tc.opts...)
			expectStatus(t, rec, tc.want)
			if strings.Contains(rec.Body.String(), "tls") || strings.Contains(rec.Body.String(), "PRIVATE") {
				t.Fatalf("body leaked: %q", rec.Body.String())
			}
		})
	}

	// An unknown exposure is a 404 on this route too, so bundles cannot be
	// used to probe for names.
	expectStatus(t, h.do("/bundles/no-such-exposure"), http.StatusNotFound)
	// From outside the allow-list, a real exposure and an invented one are
	// indistinguishable.
	known := h.do("/bundles/my-cert", from("192.0.2.1:1"))
	fake := h.do("/bundles/no-such-exposure", from("192.0.2.1:1"))
	if known.Code != fake.Code || known.Body.String() != fake.Body.String() {
		t.Fatal("bundle route distinguishes a configured exposure from an unknown one")
	}

	// A Secret that has never existed is 503, as for a single key.
	expectStatus(t, h.do("/bundles/pending"), http.StatusServiceUnavailable)

	// Deleted while running.
	h.api.Delete(certRef)
	h.waitAbsent(certRef)
	expectStatus(t, h.do("/bundles/my-cert"), http.StatusServiceUnavailable)
}

func TestBundleMethods(t *testing.T) {
	h := newHarness(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := h.do("/bundles/my-cert", withMethod(m))
		expectStatus(t, rec, http.StatusMethodNotAllowed)
		if rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
		}
	}
	full := h.do("/bundles/my-cert")
	rec := h.do("/bundles/my-cert", withMethod(http.MethodHead))
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.Len() != 0 {
		t.Fatal("HEAD must send headers only")
	}
	if rec.Header().Get("Content-Length") != fmt.Sprint(full.Body.Len()) {
		t.Fatalf("HEAD Content-Length = %q, want %d", rec.Header().Get("Content-Length"), full.Body.Len())
	}
	if rec.Header().Get("ETag") != full.Header().Get("ETag") {
		t.Fatal("HEAD and GET disagree about the ETag")
	}
}

func TestMalformedBundlePathsRejected(t *testing.T) {
	h := newHarness(t)
	h.source.reset()
	paths := []string{
		"/bundles",
		"/bundles/",
		"/bundles/my-cert/",
		"/bundles/my-cert/tls.crt",
		"/bundles/my-cert/..",
		"/bundles/../secrets/my-cert/tls.crt",
		"/bundles/%2e%2e",
		"/bundles/my%2dcert",
		"/bundles/MY-CERT",
		"/bundles//my-cert",
		"//bundles/my-cert",
		"/BUNDLES/my-cert",
		"/v1/bundles/my-cert",
		"/bundles/" + strings.Repeat("a", 254),
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			rec := h.do(p)
			expectStatus(t, rec, http.StatusNotFound)
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("redirected to %q", loc)
			}
		})
	}
	if refs := h.source.lookups(); len(refs) != 0 {
		t.Fatalf("malformed bundle paths caused lookups: %v", refs)
	}
}

func TestMalformedPathsRejected(t *testing.T) {
	h := newHarness(t)
	h.source.reset()
	paths := []string{
		"/secrets/../foo",
		"/secrets/foo/../../bar",
		"/secrets/foo/bar/baz",
		"/secrets/foo/%2e%2e",
		"/secrets/foo/%2fetc",
		"/secrets/foo/foo%2fbar",
		"/secrets/my-cert/foo/bar",
		"/secrets/my-cert/../foo",
		"/secrets/my-cert/../my-cert/tls.crt",
		"/secrets/my-cert/%2e%2e/foo",
		"/secrets/my-cert/foo%2fbar",
		"/secrets/my-cert/tls.crt%2f",
		"/secrets/my-cert/%2e%2e",
		"/secrets/my-cert/..",
		"/secrets/my-cert/.",
		"/secrets/my-cert/tls%2ecrt",
		"/secrets/my%2dcert/tls.crt",
		"/secrets/my-cert/%74ls.crt",
		"/secrets/my-cert/tls.crt%00",
		"/secrets/my-cert/%5c..%5ctls.key",
		"/secrets/my-cert/tls.crt/",
		"/secrets/my-cert//tls.crt",
		"/secrets//tls.crt",
		"//secrets/my-cert/tls.crt",
		"/secrets/./my-cert/tls.crt",
		"/SECRETS/my-cert/tls.crt",
		"/secrets/MY-CERT/tls.crt",
		"/secrets/my-cert/tls.crt;x=1",
		"/secrets/my-cert/" + strings.Repeat("a", 254),
		"/v1/secrets/my-cert/tls.crt",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			rec := h.do(p)
			expectStatus(t, rec, http.StatusNotFound)
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("redirected to %q", loc)
			}
		})
	}
	if refs := h.source.lookups(); len(refs) != 0 {
		t.Fatalf("malformed paths caused lookups: %v", refs)
	}
}

func TestNoEnumeration(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/", "/secrets", "/secrets/", "/secrets/my-cert", "/secrets/my-cert/"} {
		rec := h.do(p)
		expectStatus(t, rec, http.StatusNotFound)
		body := rec.Body.String()
		if strings.Contains(body, "my-cert") || strings.Contains(body, "tls.crt") {
			t.Fatalf("%s leaked names: %q", p, body)
		}
	}
	// "keys" is just a Secret key name that does not exist.
	expectStatus(t, h.do("/secrets/my-cert/keys"), http.StatusNotFound)
}

func TestQueryStringIgnored(t *testing.T) {
	h := newHarness(t)
	expectStatus(t, h.do("/secrets/my-cert/tls.crt?nocache=1"), http.StatusOK)
}

func TestMethods(t *testing.T) {
	h := newHarness(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := h.do("/secrets/my-cert/tls.crt", withMethod(m))
		expectStatus(t, rec, http.StatusMethodNotAllowed)
		if rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
		}
	}
	rec := h.do("/secrets/my-cert/tls.crt", withMethod(http.MethodHead))
	expectStatus(t, rec, http.StatusOK)
	if rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != fmt.Sprint(len(certPEM)) {
		t.Fatal("HEAD must send headers only")
	}
}

func TestProbesAndMetricsAreNotOnTheSecretsListener(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		for _, opt := range []reqOption{withAuth(username, password), from("192.0.2.1:1")} {
			rec := h.do(p, opt)
			expectStatus(t, rec, http.StatusNotFound)
			if strings.Contains(rec.Body.String(), "kube_secret_gateway") {
				t.Fatalf("%s leaked metrics", p)
			}
		}
	}
}

func TestMetricsEndpointAndRequestCounters(t *testing.T) {
	h := newHarness(t)
	h.do("/secrets/my-cert/tls.crt")
	h.do("/secrets/my-cert/tls.crt", withoutAuth())
	h.do("/secrets/my-cert/tls.crt", from("192.0.2.1:1"))
	h.do("/secrets/pending/tls.crt")
	h.do("/secrets/public-only/tls.key")
	h.do("/secrets/my-cert/tls.crt", withHeader("If-None-Match", h.etag(certRef, certPEM)))
	for i := range 50 {
		h.do(fmt.Sprintf("/secrets/probe-%d/key-%d", i, i))
		h.do(fmt.Sprintf("/random/%d", i))
		h.do(fmt.Sprintf("/secrets/my-cert/missing-%d", i))
	}

	rec := httptest.NewRecorder()
	h.metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	expectStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, want := range []string{
		`kube_secret_gateway_http_requests_total{export="my-cert",reason="served",status="200"} 1`,
		`kube_secret_gateway_http_requests_total{export="my-cert",reason="not_modified",status="304"} 1`,
		`kube_secret_gateway_http_requests_total{export="my-cert",reason="unauthorized",status="401"} 1`,
		`kube_secret_gateway_http_requests_total{export="my-cert",reason="client_not_allowed",status="404"} 1`,
		`kube_secret_gateway_http_requests_total{export="my-cert",reason="key_not_found",status="404"} 50`,
		`kube_secret_gateway_http_requests_total{export="pending",reason="source_secret_unavailable",status="503"} 1`,
		`kube_secret_gateway_http_requests_total{export="public-only",reason="key_not_found",status="404"} 1`,
		`kube_secret_gateway_http_requests_total{export="_unknown",reason="unknown_exposure",status="404"} 50`,
		`kube_secret_gateway_http_requests_total{export="_unknown",reason="no_route",status="404"} 50`,
		`kube_secret_gateway_source_secret_present{export="pending",namespace="certificates",secret="not-created-yet"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	// Requested names never become label values.
	for _, leaked := range []string{"probe-", "key-1", "random", "missing-"} {
		if strings.Contains(body, leaked) {
			t.Errorf("request data %q became part of the metrics", leaked)
		}
	}
	if n := countSeries(t, h.metrics.Registry(), "kube_secret_gateway_http_requests_total"); n != 9 {
		t.Errorf("got %d request series, want 9", n)
	}
}

func countSeries(t *testing.T, reg *prometheus.Registry, name string) int {
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

func TestLogsNeverContainSecretsOrCredentials(t *testing.T) {
	h := newHarness(t)
	h.do("/secrets/my-cert/tls.key")
	h.do("/secrets/my-cert/tls.crt", withAuth(username, "wrong-password-attempt"))
	h.do("/secrets/my-cert/tls.crt", withAuth("password-typed-as-username", password))
	h.do("/secrets/unknown/tls.crt?token=query-secret")
	h.do("/secrets/my-cert/tls.crt", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "10.10.30.40"))
	rv := h.api.Apply(authRef, credentials(username, "rotated-secret-password"))
	h.waitVersion(authRef, rv)
	h.do("/secrets/my-cert/tls.crt", withAuth(username, "rotated-secret-password"))

	logs := h.logs.String()
	if !strings.Contains(logs, `"export":"my-cert"`) || !strings.Contains(logs, `"client_ip":"10.10.30.40"`) {
		t.Fatalf("expected request logs, got:\n%s", logs)
	}
	forbidden := []string{
		password, "wrong-password-attempt", "password-typed-as-username", "rotated-secret-password", "query-secret",
		"PRIVATE-KEY-MATERIAL", "BEGIN CERTIFICATE", "Basic ",
		base64.StdEncoding.EncodeToString([]byte(username + ":" + password)),
	}
	for _, s := range forbidden {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain %q:\n%s", s, logs)
		}
	}
}

func TestPanicBecomesInternalServerError(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	m, err := metrics.New(cfg.Exposures, resources.NewManager(kubetest.New(), nil, resources.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	handler, err := server.New(server.Options{
		Exposures: cfg.Exposures,
		Secrets:   panickingSource{},
		ClientIP:  clientip.NewResolver(nil),
		Observer:  m,
		Logger:    slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/secrets/my-cert/tls.crt", nil)
	r.RemoteAddr = "10.10.30.40:1"
	r.SetBasicAuth(username, password)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	expectStatus(t, rec, http.StatusInternalServerError)
	if rec.Body.String() != "Internal Server Error\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if strings.Contains(logs.String(), "sensitive panic detail") {
		t.Fatal("panic value logged")
	}
}

type panickingSource struct{}

func (panickingSource) Secret(exposure.SecretRef) resources.Secret {
	panic("sensitive panic detail")
}

func TestNewRejectsIncompleteOrDuplicateOptions(t *testing.T) {
	if _, err := server.New(server.Options{}); err == nil {
		t.Fatal("incomplete options accepted")
	}
	e := exposure.Exposure{Name: "dup"}
	_, err := server.New(server.Options{
		Exposures: []exposure.Exposure{e, e},
		Secrets:   panickingSource{},
		ClientIP:  clientip.NewResolver(nil),
		Observer:  nopObserver{},
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("duplicate exposure names accepted")
	}
}

type nopObserver struct{}

func (nopObserver) ObserveRequest(string, int, string) {}

func TestHTTPServerLimits(t *testing.T) {
	srv := server.NewHTTPServer(http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("server limits not set: %+v", srv)
	}
}

// TestRawRequestsThroughRealServer sends request lines exactly as written,
// so neither a client library nor the test helper can normalize the path.
func TestRawRequestsThroughRealServer(t *testing.T) {
	h := newHarness(t)
	srv := server.NewHTTPServer(h.handler, slog.New(slog.DiscardHandler))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Loopback is an allowed client of my-cert, so the well-formed path is
	// served. Anything malformed must be rejected before routing reaches an
	// exposure, with 404 (our router) or 400 (net/http itself).
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	send := func(target string) (int, http.Header) {
		t.Helper()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: gateway\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n", target, auth)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header
	}

	if code, _ := send("/secrets/my-cert/tls.crt"); code != http.StatusOK {
		t.Fatalf("valid path from loopback = %d, want 200", code)
	}
	for _, target := range []string{
		"/secrets/../foo",
		"/secrets/foo/../../bar",
		"/secrets/my-cert/../my-cert/tls.crt",
		"/secrets/./my-cert/tls.crt",
		"/secrets/my-cert/./tls.crt",
		"/secrets/my-cert/%2e%2e/tls.key",
		"/secrets/my-cert/foo%2fbar",
		"/secrets/my-cert/%zz",
		"/secrets/my-cert/tls.crt/..",
		"http://gateway/secrets/my-cert/../x",
		"*",
	} {
		code, hdr := send(target)
		if code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 404 or 400", target, code)
		}
		if loc := hdr.Get("Location"); loc != "" {
			t.Errorf("%s: redirected to %q", target, loc)
		}
	}
}

type countingSource struct {
	inner server.SecretSource
	mu    sync.Mutex
	refs  []exposure.SecretRef
}

func (c *countingSource) Secret(ref exposure.SecretRef) resources.Secret {
	c.mu.Lock()
	c.refs = append(c.refs, ref)
	c.mu.Unlock()
	return c.inner.Secret(ref)
}

func (c *countingSource) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refs = nil
}

func (c *countingSource) lookups() []exposure.SecretRef {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]exposure.SecretRef(nil), c.refs...)
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
