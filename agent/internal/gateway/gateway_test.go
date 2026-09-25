package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway-agent/internal/config"
	"kube-secret-gateway-agent/internal/gateway"
)

// newClient returns a client pointed at base.
func newClient(t *testing.T, base string, caFile string) *gateway.Client {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	c, err := gateway.New(config.Gateway{URL: u, CAFile: caFile, Timeout: 5 * time.Second}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fetch(t *testing.T, c *gateway.Client, exposure, etag string) (*gateway.Result, error) {
	t.Helper()
	return c.Fetch(context.Background(), exposure, etag, "fetcher", "hunter2")
}

// The request must be exactly what the gateway's routing accepts: one GET to
// /exposures/{name}, with Basic Auth and the conditional header.
func TestRequestShape(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("ETag", `"hmac-sha256:abc"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tls.crt":"WA=="}`))
	}))
	defer srv.Close()

	result, err := fetch(t, newClient(t, srv.URL+"/base/", ""), "my-cert", `"hmac-sha256:old"`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != http.MethodGet {
		t.Fatalf("method = %s", got.Method)
	}
	// A trailing slash on the base URL must not produce a double slash.
	if got.URL.Path != "/base/exposures/my-cert" {
		t.Fatalf("path = %q", got.URL.Path)
	}
	if user, pass, ok := got.BasicAuth(); !ok || user != "fetcher" || pass != "hunter2" {
		t.Fatalf("basic auth = %q/%q ok=%v", user, pass, ok)
	}
	if h := got.Header.Get("If-None-Match"); h != `"hmac-sha256:old"` {
		t.Fatalf("If-None-Match = %q", h)
	}
	if h := got.Header.Get("User-Agent"); !strings.HasPrefix(h, "kube-secret-gateway-agent/") {
		t.Fatalf("User-Agent = %q", h)
	}
	if string(result.Values["tls.crt"]) != "X" || result.ETag != `"hmac-sha256:abc"` {
		t.Fatalf("result = %+v", result)
	}
}

// An empty ETag means "fetch whatever you have": no conditional header.
func TestNoConditionalHeaderWithoutAnETag(t *testing.T) {
	var sent string
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, present = r.Header.Get("If-None-Match"), r.Header.Values("If-None-Match") != nil
		w.Header().Set("ETag", `"t"`)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := fetch(t, newClient(t, srv.URL, ""), "my-cert", ""); err != nil {
		t.Fatal(err)
	}
	if present || sent != "" {
		t.Fatalf("sent If-None-Match %q with no stored ETag", sent)
	}
}

func TestNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	_, err := fetch(t, newClient(t, srv.URL, ""), "my-cert", `"t"`)
	if !errors.Is(err, gateway.ErrNotModified) {
		t.Fatalf("err = %v, want ErrNotModified", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		etag string
		body string
		want string
	}{
		{"no etag", "", `{"a":"YQ=="}`, "without an ETag"},
		{"not json", `"t"`, `not json`, "malformed response"},
		{"json null", `"t"`, `null`, "JSON null"},
		{"json array", `"t"`, `["a"]`, "malformed response"},
		{"values not base64", `"t"`, `{"a":"!!!not base64!!!"}`, "malformed response"},
		{"trailing data", `"t"`, `{"a":"YQ=="}{"b":"Yg=="}`, "trailing data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.etag != "" {
					w.Header().Set("ETag", tc.etag)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := fetch(t, newClient(t, srv.URL, ""), "my-cert", "")
			if err == nil {
				t.Fatalf("accepted a malformed response, wanted %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Each status the gateway can return has to be explained, because several of
// them cover more than one situation on purpose.
func TestStatusErrorsExplainWhatToCheck(t *testing.T) {
	for _, tc := range []struct {
		status int
		wants  []string
	}{
		{http.StatusUnauthorized, []string{"401", "username or password"}},
		{http.StatusNotFound, []string{"404", "not configured", "allowedCidrs"}},
		{http.StatusServiceUnavailable, []string{"503", "configured key"}},
		{http.StatusMethodNotAllowed, []string{"405", "not a kube-secret-gateway exposure endpoint"}},
		{http.StatusBadGateway, []string{"unexpected status"}},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(tc.status), tc.status)
			}))
			defer srv.Close()
			_, err := fetch(t, newClient(t, srv.URL, ""), "my-cert", "")
			if err == nil {
				t.Fatalf("status %d produced no error", tc.status)
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %q, want it to mention %q", err, want)
				}
			}
			// The exposure is named, and the password never is.
			if !strings.Contains(err.Error(), "my-cert") || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("err = %q", err)
			}
		})
	}
}

func TestOversizedExposureIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"t"`)
		_, _ = w.Write([]byte(`{"a":"`))
		// More base64 than MaxExposureBytes, never closed.
		chunk := strings.Repeat("QUFB", 4096)
		for written := 0; written < gateway.MaxExposureBytes+len(chunk); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	if _, err := fetch(t, newClient(t, srv.URL, ""), "my-cert", ""); err == nil {
		t.Fatal("an unbounded body was accepted")
	}
}

func TestContextCancellationStopsAFetch(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := newClient(t, srv.URL, "").Fetch(ctx, "my-cert", "", "fetcher", "hunter2")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestCAFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing", func(t *testing.T) {
		u, _ := url.Parse("https://gateway.example.com")
		_, err := gateway.New(config.Gateway{URL: u, CAFile: filepath.Join(dir, "absent.pem")}, "test")
		if err == nil || !strings.Contains(err.Error(), "caFile") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.pem")
		if err := os.WriteFile(path, []byte("this is not PEM\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse("https://gateway.example.com")
		_, err := gateway.New(config.Gateway{URL: u, CAFile: path}, "test")
		if err == nil || !strings.Contains(err.Error(), "no certificate found") {
			t.Fatalf("err = %v", err)
		}
	})

	// A CA file replaces the system pool, so a server the host would
	// otherwise trust is refused.
	t.Run("replaces the system pool", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"t"`)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		path := filepath.Join(dir, "other-ca.pem")
		if err := os.WriteFile(path, unrelatedCA(t), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := fetch(t, newClient(t, srv.URL, path), "my-cert", "")
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("err = %v, want a certificate verification failure", err)
		}
	})
}

// unrelatedCA is a real, self-signed certificate authority that signed nothing
// in these tests: it parses, so it proves the failure comes from verification
// rather than from loading the file.
func unrelatedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
