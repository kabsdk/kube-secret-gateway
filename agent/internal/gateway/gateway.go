// Package gateway is the HTTP client for one kube-secret-gateway.
//
// It speaks only GET /bundles/{exposure}: one request returns every key an
// exposure serves, from one version of the Secret, under one ETag. Fetching
// keys one at a time through /secrets/{exposure}/{key} cannot offer that,
// because an update can land between two requests.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"kube-secret-gateway-agent/internal/config"
)

// MaxBundleBytes caps the response body. A Kubernetes Secret holds at most
// 1 MiB, which base64 inflates by a third; the rest is headroom. The limit
// exists so that a misdirected request cannot exhaust memory.
const MaxBundleBytes = 8 << 20

// ErrNotModified reports that the gateway answered 304: the bundle is
// byte-for-byte what the ETag described, and nothing needs to be installed.
var ErrNotModified = errors.New("bundle not modified")

// Client fetches bundles. It is safe for concurrent use.
type Client struct {
	base    *url.URL
	http    *http.Client
	version string
}

// New returns a client for the configured gateway. When CAFile is set it is
// the only authority trusted for the connection, so a certificate from any
// other CA is refused even if the system pool would accept it.
func New(g config.Gateway, version string) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if g.CAFile != "" {
		pem, err := os.ReadFile(g.CAFile)
		if err != nil {
			return nil, fmt.Errorf("gateway caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gateway caFile %s: no certificate found", g.CAFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &Client{
		base:    g.URL,
		http:    &http.Client{Transport: transport, Timeout: g.Timeout},
		version: version,
	}, nil
}

// Bundle is one version of everything an exposure serves.
type Bundle struct {
	// Values are the Secret's keys, decoded. It is only the keys the exposure
	// serves, which may be more than a caller installs.
	Values map[string][]byte
	// ETag identifies this version. Sending it back as etag on the next fetch
	// yields ErrNotModified while nothing has changed.
	ETag string
}

// Fetch returns the exposure's bundle, or ErrNotModified when etag still
// describes it. An empty etag always fetches.
func (c *Client) Fetch(ctx context.Context, exposure, etag, username, password string) (*Bundle, error) {
	target := c.base.JoinPath("bundles", exposure)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kube-secret-gateway-agent/"+c.version)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.SetBasicAuth(username, password)

	resp, err := c.http.Do(req)
	if err != nil {
		// The URL is kept, but never the request headers, which carry the
		// credentials.
		return nil, fmt.Errorf("GET %s: %w", target.Redacted(), err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, ErrNotModified
	default:
		return nil, statusError(exposure, resp)
	}

	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		return nil, fmt.Errorf("exposure %q: 200 without an ETag: this is not a kube-secret-gateway bundle endpoint", exposure)
	}
	var values map[string][]byte
	dec := json.NewDecoder(io.LimitReader(resp.Body, MaxBundleBytes))
	if err := dec.Decode(&values); err != nil {
		return nil, fmt.Errorf("exposure %q: malformed bundle: %w", exposure, err)
	}
	if values == nil {
		return nil, fmt.Errorf("exposure %q: bundle is JSON null, not an object", exposure)
	}
	// A bundle is exactly one JSON object. Anything after it means the
	// response did not come from a bundle endpoint.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("exposure %q: trailing data after the bundle", exposure)
	}
	return &Bundle{Values: values, ETag: newETag}, nil
}

// statusError turns a response into an error that says what to check. The
// gateway deliberately answers several different situations with the same
// status, so the text names each of them rather than guessing.
func statusError(exposure string, resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("exposure %q: 401: the username or password is wrong", exposure)
	case http.StatusNotFound:
		return fmt.Errorf("exposure %q: 404: either the exposure is not configured on the gateway, "+
			"or this client's address is outside its allowedCidrs, or the gateway does not serve "+
			"/bundles/ yet", exposure)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("exposure %q: 503: the gateway is running but a Secret is not in the "+
			"expected state, such as a key promised by includeKeys that the Secret does not have; "+
			"check the gateway's logs and metrics", exposure)
	case http.StatusMethodNotAllowed:
		return fmt.Errorf("exposure %q: 405: the URL is not a kube-secret-gateway bundle endpoint", exposure)
	default:
		return fmt.Errorf("exposure %q: unexpected status %s", exposure, resp.Status)
	}
}

// Timeout reports the per-request timeout, for logging at startup.
func (c *Client) Timeout() time.Duration { return c.http.Timeout }

// BaseURL reports the gateway base URL, for logging at startup.
func (c *Client) BaseURL() string { return c.base.Redacted() }
