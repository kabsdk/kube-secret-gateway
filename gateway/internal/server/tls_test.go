package server_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway/internal/server"
	"kube-secret-gateway/internal/testcerts"
)

// mountSecret lays out files the way the kubelet projects a Secret volume:
// tls.crt and tls.key are symlinks through "..data" into a versioned
// directory, and an update atomically repoints "..data".
func mountSecret(t *testing.T, dir string, generation int, certPEM, keyPEM []byte) {
	t.Helper()
	gen := filepath.Join(dir, fmt.Sprintf("..gen_%d", generation))
	must(t, os.Mkdir(gen, 0o755))
	must(t, os.WriteFile(filepath.Join(gen, "tls.crt"), certPEM, 0o600))
	must(t, os.WriteFile(filepath.Join(gen, "tls.key"), keyPEM, 0o600))
	tmp := filepath.Join(dir, "..data_tmp")
	must(t, os.Symlink(filepath.Base(gen), tmp))
	must(t, os.Rename(tmp, filepath.Join(dir, "..data")))
	for _, name := range []string{"tls.crt", "tls.key"} {
		link := filepath.Join(dir, name)
		if _, err := os.Lstat(link); os.IsNotExist(err) {
			must(t, os.Symlink(filepath.Join("..data", name), link))
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// serveTLS runs a TLS server with the reloader's certificate and returns its
// address.
func serveTLS(t *testing.T, r *server.CertificateReloader) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	srv := server.NewHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}), slog.New(slog.DiscardHandler))
	srv.TLSConfig = server.TLSConfig(r)
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestTLSServesAndReloadsCertificate(t *testing.T) {
	ca := testcerts.NewAuthority(t)
	dir := t.TempDir()
	cert1, key1, serial1 := ca.Issue(t, "127.0.0.1", "kube-secret-gateway.certificates.svc")
	mountSecret(t, dir, 1, cert1, key1)

	r, err := server.NewCertificateReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	must(t, err)
	if r.NotAfter().IsZero() {
		t.Fatal("NotAfter unknown")
	}
	addr := serveTLS(t, r)
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.Run(ctx, 5*time.Millisecond, slog.New(slog.NewJSONHandler(logs, nil)))

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: ca.Pool()},
		DisableKeepAlives: true, // every request performs a fresh handshake
	}}
	servedSerial := func() *big.Int {
		t.Helper()
		resp, err := client.Get("https://" + addr + "/")
		must(t, err)
		resp.Body.Close()
		return resp.TLS.PeerCertificates[0].SerialNumber
	}
	if got := servedSerial(); got.Cmp(serial1) != 0 {
		t.Fatalf("served serial %v, want %v", got, serial1)
	}

	// Renewal, as cert-manager and the kubelet perform it.
	cert2, key2, serial2 := ca.Issue(t, "127.0.0.1", "kube-secret-gateway.certificates.svc")
	mountSecret(t, dir, 2, cert2, key2)
	waitFor(t, "renewed certificate served", func() bool { return servedSerial().Cmp(serial2) == 0 })

	// A broken update (certificate and key do not match) is rejected, and
	// the previous certificate stays in service.
	cert3, _, _ := ca.Issue(t, "127.0.0.1")
	mountSecret(t, dir, 3, cert3, key2)
	waitFor(t, "reload failure logged", func() bool {
		return strings.Contains(logs.String(), "reloading TLS certificate failed")
	})
	if got := servedSerial(); got.Cmp(serial2) != 0 {
		t.Fatalf("after a broken update the served serial is %v, want %v", got, serial2)
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("key material in logs")
	}
}

func TestCertificateReloaderRejectsUnusableFiles(t *testing.T) {
	ca := testcerts.NewAuthority(t)
	dir := t.TempDir()
	certPEM, keyPEM, _ := ca.Issue(t, "localhost")
	_, otherKey, _ := ca.Issue(t, "localhost")
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, data, 0o600))
		return p
	}
	cert, key := write("tls.crt", certPEM), write("tls.key", keyPEM)
	garbage := write("garbage", []byte("not a certificate"))
	mismatched := write("other.key", otherKey)

	for name, files := range map[string][2]string{
		"missing certificate":   {filepath.Join(dir, "absent.crt"), key},
		"missing key":           {cert, filepath.Join(dir, "absent.key")},
		"garbage certificate":   {garbage, key},
		"garbage key":           {cert, garbage},
		"key of another cert":   {cert, mismatched},
		"key given as the cert": {key, key},
	} {
		_, err := server.NewCertificateReloader(files[0], files[1])
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: error contains key material: %v", name, err)
		}
	}
	if _, err := server.NewCertificateReloader(cert, key); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
}

func TestTLSRejectsOldProtocolVersions(t *testing.T) {
	ca := testcerts.NewAuthority(t)
	dir := t.TempDir()
	certPEM, keyPEM, _ := ca.Issue(t, "127.0.0.1")
	mountSecret(t, dir, 1, certPEM, keyPEM)
	r, err := server.NewCertificateReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	must(t, err)
	addr := serveTLS(t, r)

	// The client explicitly offers TLS 1.0 and 1.1, so a failure proves the
	// server refused them rather than the client's own defaults.
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.1 handshake succeeded")
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("handshake failed for another reason: %v", err)
	}
	conn, err = tls.Dial("tcp", addr, &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS13})
	must(t, err)
	conn.Close()
}
