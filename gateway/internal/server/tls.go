package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CertificateReloader serves a TLS certificate from PEM files and picks up
// renewals without a restart. It suits a cert-manager Secret mounted as a
// volume: the kubelet swaps both files atomically when the Secret changes,
// and the reloader re-reads them periodically and switches to the new pair
// once it loads.
type CertificateReloader struct {
	certFile, keyFile string

	mu     sync.RWMutex
	cert   *tls.Certificate
	digest [2][sha256.Size]byte
}

// NewCertificateReloader loads the key pair, failing if it is unusable.
func NewCertificateReloader(certFile, keyFile string) (*CertificateReloader, error) {
	r := &CertificateReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate is the tls.Config hook serving the current certificate.
func (r *CertificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// NotAfter returns the expiry of the certificate currently served.
func (r *CertificateReloader) NotAfter() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert.Leaf == nil {
		return time.Time{}
	}
	return r.cert.Leaf.NotAfter
}

// Run re-reads the files every interval until ctx ends. A pair that does not
// load is logged, and the previous certificate stays in use.
func (r *CertificateReloader) Run(ctx context.Context, interval time.Duration, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := r.reload()
			switch {
			case err != nil:
				log.Warn("reloading TLS certificate failed; keeping the current one", "cert_file", r.certFile, "error", err)
			case changed:
				log.Info("TLS certificate reloaded", "cert_file", r.certFile, "not_after", r.NotAfter())
			}
		}
	}
}

func (r *CertificateReloader) reload() (changed bool, err error) {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return false, fmt.Errorf("read TLS certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return false, fmt.Errorf("read TLS private key: %w", err)
	}
	digest := [2][sha256.Size]byte{sha256.Sum256(certPEM), sha256.Sum256(keyPEM)}

	r.mu.RLock()
	unchanged := r.cert != nil && digest == r.digest
	r.mu.RUnlock()
	if unchanged {
		return false, nil
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("load TLS key pair from %s and %s: %w", r.certFile, r.keyFile, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cert, r.digest = &cert, digest
	return true, nil
}

// TLSConfig returns a server configuration that serves r's certificate over
// TLS 1.2 or newer with Go's default cipher suites. Client certificates are
// not requested.
func TLSConfig(r *CertificateReloader) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.GetCertificate,
	}
}
