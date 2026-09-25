package server_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"kube-secret-gateway/internal/clientip"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/resources"
	"kube-secret-gateway/internal/server"
)

const (
	username = "fetcher"
	password = "correct horse battery staple"
)

var (
	sourceRef  = exposure.SecretRef{Namespace: "certificates", Name: "website-tls"}
	authRef    = exposure.SecretRef{Namespace: "readers", Name: "nginx-reader"}
	missingRef = exposure.SecretRef{Namespace: "certificates", Name: "incomplete"}
)

type harness struct {
	t        *testing.T
	source   *memorySource
	observer *observer
	handler  http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	exposures := []exposure.Exposure{
		{
			Name: "nginx-tls", Source: sourceRef, Keys: []string{"tls.key", "tls.crt"},
			AllowedCIDRs: mustPrefixes("10.10.30.40/32", "127.0.0.1/32", "2001:db8::/64"),
			Auth:         exposure.Auth{SecretRef: authRef},
		},
		{
			Name: "nginx-cert", Source: sourceRef, Keys: []string{"tls.crt"},
			AllowedCIDRs: mustPrefixes("10.10.30.40/32"), Auth: exposure.Auth{SecretRef: authRef},
		},
		{
			Name: "incomplete", Source: missingRef, Keys: []string{"present", "missing"},
			AllowedCIDRs: mustPrefixes("10.10.30.40/32"), Auth: exposure.Auth{SecretRef: authRef},
		},
	}
	src := &memorySource{secrets: map[exposure.SecretRef]resources.Secret{}}
	src.set(sourceRef, "source-uid", map[string][]byte{
		"tls.crt": []byte("CERT"), "tls.key": []byte("KEY"), "extra": []byte("IGNORED"),
	})
	src.set(authRef, "auth-uid", credentials(username, password))
	src.set(missingRef, "missing-uid", map[string][]byte{"present": []byte("yes")})
	obs := &observer{}
	h, err := server.New(server.Options{
		Exposures: exposures,
		Secrets:   src,
		ClientIP:  clientip.NewResolver(mustPrefixes("10.42.0.0/16")),
		Observer:  obs,
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, source: src, observer: obs, handler: h}
}

func credentials(user, pass string) map[string][]byte {
	return map[string][]byte{"username": []byte(user), "password": []byte(pass)}
}

func mustPrefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, value := range values {
		out[i] = netip.MustParsePrefix(value)
	}
	return out
}

type requestOption func(*http.Request)

func from(addr string) requestOption { return func(r *http.Request) { r.RemoteAddr = addr } }
func withAuth(user, pass string) requestOption {
	return func(r *http.Request) { r.SetBasicAuth(user, pass) }
}
func withoutAuth() requestOption { return func(r *http.Request) { r.Header.Del("Authorization") } }
func withHeader(name, value string) requestOption {
	return func(r *http.Request) { r.Header.Add(name, value) }
}
func withMethod(method string) requestOption { return func(r *http.Request) { r.Method = method } }
func withBody(body string) requestOption {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
	}
}

func withUnknownLengthBody(body string) requestOption {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = -1
		r.TransferEncoding = nil
	}
}

func (h *harness) do(target string, opts ...requestOption) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = "10.10.30.40:1234"
	r.SetBasicAuth(username, password)
	for _, opt := range opts {
		opt(r)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, want, rec.Body.String())
	}
}

func TestGETExposureCanonicalSnapshot(t *testing.T) {
	h := newHarness(t)
	rec := h.do("/exposures/nginx-tls")
	expectStatus(t, rec, http.StatusOK)
	const want = `{"tls.crt":"Q0VSVA==","tls.key":"S0VZ"}`
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	var decoded map[string][]byte
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["tls.crt"]) != "CERT" || string(decoded["tls.key"]) != "KEY" || len(decoded) != 2 {
		t.Fatalf("decoded snapshot = %q", decoded)
	}
	for name, want := range map[string]string{
		"Content-Type": "application/json", "Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff", "Content-Length": fmt.Sprint(len(want)),
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("ETag missing")
	}
}

func TestBinaryAndEmptyValuesRoundTrip(t *testing.T) {
	h := newHarness(t)
	binary := []byte{0x00, 0xff, 0xfe, '\r', '\n', 0x80, 0x00}
	h.source.set(sourceRef, "binary-uid", map[string][]byte{
		"tls.crt": binary,
		"tls.key": {},
	})
	rec := h.do("/exposures/nginx-tls")
	expectStatus(t, rec, http.StatusOK)
	var decoded map[string][]byte
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded["tls.crt"], binary) || len(decoded["tls.key"]) != 0 {
		t.Fatalf("decoded snapshot = %q", decoded)
	}
}

func TestOneKeyExposureAndHEAD(t *testing.T) {
	h := newHarness(t)
	get := h.do("/exposures/nginx-cert")
	head := h.do("/exposures/nginx-cert", withMethod(http.MethodHead))
	expectStatus(t, get, http.StatusOK)
	expectStatus(t, head, http.StatusOK)
	if get.Body.String() != `{"tls.crt":"Q0VSVA=="}` || head.Body.Len() != 0 {
		t.Fatalf("GET body %q, HEAD body %q", get.Body.String(), head.Body.String())
	}
	for _, name := range []string{"Content-Type", "Content-Length", "ETag", "Cache-Control", "X-Content-Type-Options"} {
		if get.Header().Get(name) != head.Header().Get(name) {
			t.Errorf("%s differs between GET and HEAD", name)
		}
	}
}

func TestConditionalGETAndHEAD(t *testing.T) {
	h := newHarness(t)
	first := h.do("/exposures/nginx-tls")
	etag := first.Header().Get("ETag")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := h.do("/exposures/nginx-tls", withMethod(method), withHeader("If-None-Match", etag))
		expectStatus(t, rec, http.StatusNotModified)
		if rec.Body.Len() != 0 || rec.Header().Get("ETag") != etag {
			t.Fatalf("%s conditional response is wrong", method)
		}
	}
}

func TestExposureETagTracksCompleteConfiguredSnapshot(t *testing.T) {
	h := newHarness(t)
	first := h.do("/exposures/nginx-tls")
	firstTag := first.Header().Get("ETag")
	// An unconfigured source key is not part of this exposure.
	h.source.set(sourceRef, "source-uid", map[string][]byte{
		"tls.crt": []byte("CERT"), "tls.key": []byte("KEY"), "extra": []byte("CHANGED"),
	})
	if got := h.do("/exposures/nginx-tls").Header().Get("ETag"); got != firstTag {
		t.Fatal("ETag changed for an unconfigured key")
	}
	// Any configured key changes the complete exposure ETag.
	h.source.set(sourceRef, "source-uid", map[string][]byte{
		"tls.crt": []byte("NEW"), "tls.key": []byte("KEY"), "extra": []byte("CHANGED"),
	})
	rec := h.do("/exposures/nginx-tls", withHeader("If-None-Match", firstTag))
	expectStatus(t, rec, http.StatusOK)
	if rec.Header().Get("ETag") == firstTag {
		t.Fatal("ETag did not change")
	}
}

func TestMissingConfiguredKeyNeverReturnsPartialSnapshot(t *testing.T) {
	h := newHarness(t)
	rec := h.do("/exposures/incomplete")
	expectStatus(t, rec, http.StatusServiceUnavailable)
	if rec.Body.String() != "Service Unavailable\n" || strings.Contains(rec.Body.String(), "present") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := h.observer.last(); got.reason != server.ReasonConfiguredKeyMissing {
		t.Fatalf("reason = %q", got.reason)
	}
	h.source.set(missingRef, "missing-uid", map[string][]byte{"present": []byte("yes"), "missing": []byte("now")})
	expectStatus(t, h.do("/exposures/incomplete"), http.StatusOK)
}

func TestAuthenticationAndPasswordRotation(t *testing.T) {
	h := newHarness(t)
	for _, opts := range [][]requestOption{{withoutAuth()}, {withAuth(username, "wrong")}, {withAuth("wrong", password)}} {
		rec := h.do("/exposures/nginx-tls", opts...)
		expectStatus(t, rec, http.StatusUnauthorized)
		if rec.Header().Get("WWW-Authenticate") != `Basic realm="kube-secret-gateway"` {
			t.Fatal("Basic challenge missing")
		}
	}
	h.source.set(authRef, "auth-uid", credentials(username, "rotated"))
	expectStatus(t, h.do("/exposures/nginx-tls"), http.StatusUnauthorized)
	expectStatus(t, h.do("/exposures/nginx-tls", withAuth(username, "rotated")), http.StatusOK)

	h.source.set(authRef, "auth-uid", map[string][]byte{"username": []byte(username)})
	expectStatus(t, h.do("/exposures/nginx-tls", withAuth(username, "rotated")), http.StatusServiceUnavailable)
	h.source.remove(authRef)
	expectStatus(t, h.do("/exposures/nginx-tls", withAuth(username, "rotated")), http.StatusServiceUnavailable)
}

func TestCIDRRestrictionsAndTrustedProxies(t *testing.T) {
	h := newHarness(t)
	for _, addr := range []string{"10.10.30.40:1", "[2001:db8::7]:1", "[::ffff:10.10.30.40]:1"} {
		expectStatus(t, h.do("/exposures/nginx-tls", from(addr)), http.StatusOK)
	}
	for _, addr := range []string{"10.10.30.41:1", "[2001:db9::7]:1"} {
		expectStatus(t, h.do("/exposures/nginx-tls", from(addr)), http.StatusNotFound)
	}
	expectStatus(t, h.do("/exposures/nginx-tls", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "10.10.30.40")), http.StatusOK)
	expectStatus(t, h.do("/exposures/nginx-tls", from("198.51.100.7:1"), withHeader("X-Forwarded-For", "10.10.30.40")), http.StatusNotFound)
	expectStatus(t, h.do("/exposures/nginx-tls", from("10.42.0.5:1"), withHeader("X-Forwarded-For", "garbage")), http.StatusNotFound)
}

func TestUnknownExposureAndEnumerationProtection(t *testing.T) {
	h := newHarness(t)
	h.source.resetLookups()
	unknown := h.do("/exposures/unknown")
	denied := h.do("/exposures/nginx-tls", from("192.0.2.1:1"))
	expectStatus(t, unknown, http.StatusNotFound)
	if unknown.Body.String() != denied.Body.String() || !equalHeaders(unknown.Header(), denied.Header()) {
		t.Fatal("denied configured exposure differs from unknown exposure")
	}
	if got := h.source.lookups(); len(got) != 0 {
		t.Fatalf("unauthorized names caused Secret lookups: %v", got)
	}
}

func TestOnlyExposureRouteExists(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		"/secrets/nginx-tls/tls.crt", "/bundles/nginx-tls", "/exposures", "/exposures/",
		"/exposures/nginx-tls/", "/exposures/nginx-tls/tls.crt", "/exposures/../nginx-tls",
		"/exposures/%6eginx-tls", "/exposures/nginx%2dtls", "/exposures/NGINX", "//exposures/nginx-tls",
		"/exposures/nginx-tls?key=tls.crt", "/exposures/nginx-tls?",
	} {
		expectStatus(t, h.do(path), http.StatusNotFound)
	}
	expectStatus(t, h.do("/exposures/nginx-tls", withBody("tls.crt")), http.StatusNotFound)
	expectStatus(t, h.do("/exposures/nginx-tls", withUnknownLengthBody("tls.crt")), http.StatusNotFound)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		rec := h.do("/exposures/nginx-tls", withMethod(method))
		expectStatus(t, rec, http.StatusMethodNotAllowed)
		if rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatal("Allow header wrong")
		}
	}
}

func TestRequestOutcomes(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		rec    *httptest.ResponseRecorder
		reason string
	}{
		{h.do("/nope"), server.ReasonNoRoute},
		{h.do("/exposures/nope"), server.ReasonUnknownExposure},
		{h.do("/exposures/nginx-tls", withoutAuth()), server.ReasonUnauthorized},
		{h.do("/exposures/nginx-tls"), server.ReasonServed},
	}
	for _, tc := range cases {
		if got := h.observer.at(tc.rec.Code, tc.reason); !got {
			t.Errorf("missing observed outcome status=%d reason=%s", tc.rec.Code, tc.reason)
		}
	}
}

func TestRawMalformedPathsAreNotRedirected(t *testing.T) {
	h := newHarness(t)
	srv := server.NewHTTPServer(h.handler, slog.New(slog.DiscardHandler))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	send := func(target string) (int, http.Header) {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: gateway\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n", target, auth)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header
	}
	if code, _ := send("/exposures/nginx-tls"); code != http.StatusOK {
		t.Fatalf("valid path status = %d", code)
	}
	for _, target := range []string{
		"/exposures/../nginx-tls", "/exposures/./nginx-tls", "/exposures/%2e%2e",
		"/exposures/nginx%2dtls", "/exposures/nginx-tls/..", "http://gateway/exposures/../x", "*",
	} {
		code, header := send(target)
		if code != http.StatusNotFound && code != http.StatusBadRequest {
			t.Errorf("%s: status = %d", target, code)
		}
		if header.Get("Location") != "" {
			t.Errorf("%s redirected", target)
		}
	}
}

func TestNewRejectsIncompleteOrDuplicateOptions(t *testing.T) {
	if _, err := server.New(server.Options{}); err == nil {
		t.Fatal("incomplete options accepted")
	}
	e := exposure.Exposure{Name: "same"}
	_, err := server.New(server.Options{
		Exposures: []exposure.Exposure{e, e}, Secrets: &memorySource{},
		ClientIP: clientip.NewResolver(nil), Observer: &observer{}, Logger: slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("duplicate exposure accepted")
	}
}

func TestHTTPServerLimits(t *testing.T) {
	srv := server.NewHTTPServer(http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("limits not set: %+v", srv)
	}
}

func TestPanicBecomesInternalServerError(t *testing.T) {
	logs := &lockedBuffer{}
	obs := &observer{}
	h, err := server.New(server.Options{
		Exposures: []exposure.Exposure{{
			Name: "nginx-tls", Source: sourceRef, Keys: []string{"tls.crt"},
			AllowedCIDRs: mustPrefixes("10.10.30.40/32"), Auth: exposure.Auth{SecretRef: authRef},
		}},
		Secrets:  panickingSource{},
		ClientIP: clientip.NewResolver(nil),
		Observer: obs,
		Logger:   slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/exposures/nginx-tls", nil)
	r.RemoteAddr = "10.10.30.40:1"
	r.SetBasicAuth(username, password)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	expectStatus(t, rec, http.StatusInternalServerError)
	if rec.Body.String() != "Internal Server Error\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if strings.Contains(logs.String(), "sensitive panic detail") {
		t.Fatal("panic value logged")
	}
	if got := obs.last(); got.status != http.StatusInternalServerError || got.reason != server.ReasonInternalError {
		t.Fatalf("observed = %+v", got)
	}
}

type panickingSource struct{}

func (panickingSource) Secret(exposure.SecretRef) resources.Secret {
	panic("sensitive panic detail")
}

func equalHeaders(a, b http.Header) bool {
	for _, name := range []string{"Content-Type", "Cache-Control", "X-Content-Type-Options", "WWW-Authenticate"} {
		if a.Get(name) != b.Get(name) {
			return false
		}
	}
	return true
}

type memorySource struct {
	mu      sync.Mutex
	secrets map[exposure.SecretRef]resources.Secret
	refs    []exposure.SecretRef
}

func (s *memorySource) Secret(ref exposure.SecretRef) resources.Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs = append(s.refs, ref)
	secret := s.secrets[ref]
	secret.Data = cloneData(secret.Data)
	return secret
}

func (s *memorySource) set(ref exposure.SecretRef, uid string, data map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secrets == nil {
		s.secrets = make(map[exposure.SecretRef]resources.Secret)
	}
	s.secrets[ref] = resources.Secret{Present: true, Synced: true, UID: types.UID(uid), Data: cloneData(data)}
}

func (s *memorySource) remove(ref exposure.SecretRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, ref)
}

func (s *memorySource) resetLookups() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs = nil
}

func (s *memorySource) lookups() []exposure.SecretRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]exposure.SecretRef(nil), s.refs...)
}

func cloneData(data map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(data))
	for key, value := range data {
		out[key] = bytes.Clone(value)
	}
	return out
}

type observed struct {
	status int
	reason string
}

type observer struct {
	mu     sync.Mutex
	values []observed
}

// Shared helpers used by the listener-specific tests in this package.
type reqOption = requestOption

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

func (o *observer) ObserveRequest(_ string, status int, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.values = append(o.values, observed{status: status, reason: reason})
}

func (o *observer) last() observed {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.values[len(o.values)-1]
}

func (o *observer) at(status int, reason string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, value := range o.values {
		if value.status == status && value.reason == reason {
			return true
		}
	}
	return false
}
