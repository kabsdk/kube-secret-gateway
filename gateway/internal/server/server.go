// Package server implements the two HTTP listeners.
//
// The delivery listener serves only
//
//	GET|HEAD /exposures/{name}   every configured key, as canonical JSON
//
// and the metrics listener, on its own port, serves
//
//	GET /healthz                    liveness
//	GET /readyz                     readiness
//	GET /metrics                    Prometheus metrics, optionally authenticated
//
// Keeping them apart means only /exposures/ needs to be reachable
// through the ingress, and nothing on that port reveals which exposures exist.
//
// One request reads one Secret from memory once, so the response is an atomic
// snapshot and carries one ETag for the complete exposure.
//
// Routing is done on the escaped request path by this package itself rather
// than by http.ServeMux, which cleans paths and answers with redirects. A
// path must consist of exactly one valid exposure name segment, so
// percent-encoding, dot segments and extra separators are rejected before any
// lookup.
package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"kube-secret-gateway/internal/auth"
	"kube-secret-gateway/internal/clientip"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/resources"
)

// HTTP server limits.
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 32 << 10
)

const exposuresPrefix = "/exposures/"

// SecretSource provides the current state of watched Secrets. It must answer
// from memory; the handler calls it on every request.
type SecretSource interface {
	Secret(ref exposure.SecretRef) resources.Secret
}

// RequestObserver records the outcome of exposure endpoint requests. name is
// empty for requests that did not resolve to a configured exposure; reason is
// always one of the Reason constants.
type RequestObserver interface {
	ObserveRequest(name string, status int, reason string)
}

// Reasons explain a response in logs and metrics. Several map to the same
// status code on purpose, so that clients cannot tell them apart, while
// operators still can.
const (
	ReasonServed                  = "served"
	ReasonNotModified             = "not_modified"
	ReasonMethodNotAllowed        = "method_not_allowed"
	ReasonNoRoute                 = "no_route"
	ReasonUnknownExposure         = "unknown_exposure"
	ReasonClientNotAllowed        = "client_not_allowed"
	ReasonClientAddressUnresolved = "client_address_unresolved"
	ReasonAuthSecretUnavailable   = "auth_secret_unavailable"
	ReasonAuthSecretMalformed     = "auth_secret_malformed"
	ReasonUnauthorized            = "unauthorized"
	ReasonSourceSecretUnavailable = "source_secret_unavailable"
	ReasonConfiguredKeyMissing    = "configured_key_missing"
	ReasonInternalError           = "internal_error"
)

// Options configures a Handler. All fields are required.
type Options struct {
	Exposures []exposure.Exposure
	Secrets   SecretSource
	ClientIP  *clientip.Resolver
	Observer  RequestObserver
	Logger    *slog.Logger
}

// Handler serves the delivery listener.
type Handler struct {
	exposures map[string]*exposure.Exposure
	secrets   SecretSource
	clientIP  *clientip.Resolver
	observer  RequestObserver
	log       *slog.Logger
}

// New returns the handler for the delivery listener.
func New(opts Options) (*Handler, error) {
	if opts.Secrets == nil || opts.ClientIP == nil || opts.Observer == nil || opts.Logger == nil {
		return nil, errors.New("server: incomplete options")
	}
	h := &Handler{
		exposures: make(map[string]*exposure.Exposure, len(opts.Exposures)),
		secrets:   opts.Secrets,
		clientIP:  opts.ClientIP,
		observer:  opts.Observer,
		log:       opts.Logger,
	}
	for i := range opts.Exposures {
		e := opts.Exposures[i]
		if _, dup := h.exposures[e.Name]; dup {
			return nil, fmt.Errorf("server: duplicate exposure name %q", e.Name)
		}
		h.exposures[e.Name] = &e
	}
	return h, nil
}

// NewHTTPServer returns an http.Server with conservative timeouts and limits.
func NewHTTPServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// ServeHTTP handles every request on the delivery listener. Anything that is
// not a well-formed exposure path is a 404, including the probe and
// metrics paths, which live on the metrics listener.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serveRequest(w, r)
}

// outcome collects what is logged and counted for one request. It never
// holds credentials or Secret data.
type outcome struct {
	name   string // configured exposure name; empty if none matched
	key    string // missing configured key, when unhealthy
	client netip.Addr
	peer   netip.Addr
	status int
	reason string
}

func (h *Handler) serveRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	o := &outcome{}
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			// The panic value is not logged: it could contain request data.
			h.log.Error("panic while serving request", "panic_type", fmt.Sprintf("%T", p), "stack", string(debug.Stack()))
			if sw.status == 0 {
				writeError(sw, http.StatusInternalServerError)
			}
			o.status, o.reason = http.StatusInternalServerError, ReasonInternalError
		}
		h.finish(r, o, time.Since(start))
	}()
	h.handleRequest(sw, r, o)
}

// handleRequest runs the request pipeline. The order of the
// checks decides what a caller can learn about the configuration:
//
//  1. Malformed path, unknown exposure, or a client outside the exposure's
//     allowedCidrs: 404, identical in every case. From outside an allow-list,
//     an existing exposure is indistinguishable from a name that does not
//     exist, so names cannot be probed.
//  2. Authentication Secret missing or malformed: 503.
//  3. Missing or wrong credentials: 401. Nothing about keys is revealed
//     before this point.
//  4. Source Secret absent or any configured key missing: 503.
//  5. The complete exposure snapshot, or 304 if the client already has it.
func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request, o *outcome) {
	fail := func(status int, reason string) {
		o.status, o.reason = status, reason
		writeError(w, status)
	}

	// Resolved up front so that every request is logged with its client;
	// a resolution failure only takes effect at the network check below.
	client, peer, ipErr := h.clientIP.Resolve(r)
	o.client, o.peer = client, peer

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(http.StatusMethodNotAllowed, ReasonMethodNotAllowed)
		return
	}
	name, ok := parseRoute(r.URL.EscapedPath())
	if r.URL.ForceQuery || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		ok = false
	}
	if !ok {
		fail(http.StatusNotFound, ReasonNoRoute)
		return
	}
	// Only configured names are looked up; an arbitrary name never reaches
	// the resource cache or the Kubernetes API.
	exp := h.exposures[name]
	if exp == nil {
		fail(http.StatusNotFound, ReasonUnknownExposure)
		return
	}
	o.name = exp.Name
	if ipErr != nil {
		fail(http.StatusNotFound, ReasonClientAddressUnresolved)
		return
	}
	if !exp.AllowsClient(client) {
		fail(http.StatusNotFound, ReasonClientNotAllowed)
		return
	}

	authSecret := h.secrets.Secret(exp.Auth.SecretRef)
	if !authSecret.Present {
		fail(http.StatusServiceUnavailable, ReasonAuthSecretUnavailable)
		return
	}
	verifier, err := auth.NewBasic(authSecret.Data)
	if err != nil {
		fail(http.StatusServiceUnavailable, ReasonAuthSecretMalformed)
		return
	}
	if !verifier.Verify(r) {
		w.Header().Set("WWW-Authenticate", verifier.Challenge())
		fail(http.StatusUnauthorized, ReasonUnauthorized)
		return
	}

	source := h.secrets.Secret(exp.Source)
	if !source.Present {
		fail(http.StatusServiceUnavailable, ReasonSourceSecretUnavailable)
		return
	}
	missing, body := exposureBody(source.Data, exp.Keys)
	if missing != "" {
		o.key = missing
		fail(http.StatusServiceUnavailable, ReasonConfiguredKeyMissing)
		return
	}
	o.status = writeBody(w, r, body, source.UID, "application/json")
	o.reason = ReasonServed
	if o.status == http.StatusNotModified {
		o.reason = ReasonNotModified
	}
}

// parseRoute accepts exactly /exposures/{name} from the escaped path.
func parseRoute(escaped string) (string, bool) {
	name, found := strings.CutPrefix(escaped, exposuresPrefix)
	if !found || strings.Contains(name, "/") || exposure.ValidateName(name) != nil {
		return "", false
	}
	return name, true
}

// exposureBody serialises every configured key, or names the first one that
// the Kubernetes Secret does not have.
//
// Keys are sorted, so the body, and with it the ETag, depends only on the
// Secret's configured contents, never on map iteration
// order. Values are base64 so that arbitrary bytes survive JSON. Secret keys
// are restricted to [-._a-zA-Z0-9] by exposure.ValidateKey, so no key can
// contain a character that JSON would have to escape.
func exposureBody(data map[string][]byte, configured []string) (missing string, body []byte) {
	keys := append([]string(nil), configured...)
	for _, k := range keys {
		if _, ok := data[k]; !ok {
			return k, nil
		}
	}
	slices.Sort(keys)
	size := 2
	for _, k := range keys {
		size += len(k) + base64.StdEncoding.EncodedLen(len(data[k])) + 6
	}

	var b bytes.Buffer
	b.Grow(size)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`":"`)
		b.WriteString(base64.StdEncoding.EncodeToString(data[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return "", b.Bytes()
}

// ETag returns the entity tag for a response body: HMAC-SHA256 of the bytes
// served, keyed with the Secret's UID. The bytes are the canonical exposure
// body, so the tag changes exactly when any configured key changes.
//
// A plain hash of the value would let anyone who sees the header, but not
// the body (a "curl -v" in a CI log, a proxy logging response headers), test
// guesses offline, which matters for short values such as passwords. The UID
// is random, known only to those who can read the Secret from the API, and
// the same on every replica, so the tag still changes exactly when the value
// changes. Recreating a Secret gives it a new UID, which costs clients one
// extra download.
func ETag(value []byte, uid types.UID) string {
	mac := hmac.New(sha256.New, []byte(uid))
	mac.Write(value)
	return `"hmac-sha256:` + hex.EncodeToString(mac.Sum(nil)) + `"`
}

// writeBody sends the response body, or 304 if the client already has it.
func writeBody(w http.ResponseWriter, r *http.Request, value []byte, uid types.UID, contentType string) int {
	etag := ETag(value, uid)
	hdr := w.Header()
	hdr.Set("ETag", etag)
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	if etagMatches(r.Header.Values("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return http.StatusNotModified
	}
	hdr.Set("Content-Type", contentType)
	hdr.Set("Content-Length", strconv.Itoa(len(value)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(value)
	}
	return http.StatusOK
}

// etagMatches implements the weak comparison If-None-Match uses.
func etagMatches(headerValues []string, etag string) bool {
	for _, v := range headerValues {
		for candidate := range strings.SplitSeq(v, ",") {
			c := strings.TrimSpace(candidate)
			if c == "*" || strings.TrimPrefix(c, "W/") == etag {
				return true
			}
		}
	}
	return false
}

func writeError(w http.ResponseWriter, status int) {
	hdr := w.Header()
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, http.StatusText(status)+"\n")
}

func (h *Handler) finish(r *http.Request, o *outcome, elapsed time.Duration) {
	h.observer.ObserveRequest(o.name, o.status, o.reason)

	attrs := make([]slog.Attr, 0, 9)
	if o.name != "" {
		attrs = append(attrs, slog.String("exposure", o.name))
		if o.key != "" {
			attrs = append(attrs, slog.String("key", o.key))
		}
	} else {
		// Only the path is logged: never the query string or any header.
		attrs = append(attrs, slog.String("path", truncate(r.URL.EscapedPath(), 256)))
	}
	attrs = append(attrs, slog.String("method", r.Method))
	if o.client.IsValid() {
		attrs = append(attrs, slog.String("client_ip", o.client.String()))
	}
	if o.peer.IsValid() && o.peer != o.client {
		attrs = append(attrs, slog.String("peer_ip", o.peer.String()))
	}
	attrs = append(attrs,
		slog.Int("status", o.status),
		slog.String("reason", o.reason),
		slog.Duration("duration", elapsed),
	)

	level := slog.LevelInfo
	switch {
	case o.status >= 500 && o.status != http.StatusServiceUnavailable:
		level = slog.LevelError
	case o.status == http.StatusUnauthorized, o.status == http.StatusServiceUnavailable,
		o.reason == ReasonClientNotAllowed, o.reason == ReasonClientAddressUnresolved:
		level = slog.LevelWarn
	}
	h.log.LogAttrs(r.Context(), level, "request", attrs...)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

// statusWriter remembers whether a status has been written, so a recovered
// panic only writes a 500 if no response has started.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}
