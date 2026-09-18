// Package server implements the two HTTP listeners.
//
// The Secrets listener serves only
//
//	GET /secrets/{exposure}/{key}   raw Secret value
//
// and the metrics listener, on its own port, serves
//
//	GET /healthz                    liveness
//	GET /readyz                     readiness
//	GET /metrics                    Prometheus metrics, optionally authenticated
//
// Keeping them apart means only /secrets/ needs to be reachable through the
// ingress, and nothing on that port reveals which exposures exist.
//
// Routing is done on the escaped request path by this package itself rather
// than by http.ServeMux, which cleans paths and answers with redirects. A
// Secret path must consist of exactly two segments made only of characters
// that valid exposure names and Secret keys can contain, so percent-encoding,
// dot segments and extra separators are all rejected before any lookup.
package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
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

const secretsPrefix = "/secrets/"

// SecretSource provides the current state of watched Secrets. It must answer
// from memory; the handler calls it on every request.
type SecretSource interface {
	Secret(ref exposure.SecretRef) resources.Secret
}

// RequestObserver records the outcome of Secret endpoint requests. export is
// empty for requests that did not resolve to a configured exposure; reason is
// always one of the Reason constants.
type RequestObserver interface {
	ObserveRequest(export string, status int, reason string)
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
	ReasonExpectedKeyMissing      = "expected_key_missing"
	ReasonKeyNotFound             = "key_not_found"
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

// Handler serves the Secrets listener.
type Handler struct {
	exposures map[string]*exposure.Exposure
	secrets   SecretSource
	clientIP  *clientip.Resolver
	observer  RequestObserver
	log       *slog.Logger
}

// New returns the handler for the Secrets listener.
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

// ServeHTTP handles every request on the Secrets listener. Anything that is
// not a well-formed Secret path is a 404, including the probe and metrics
// paths, which live on the metrics listener.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serveSecret(w, r)
}

// outcome collects what is logged and counted for one request. It never
// holds credentials or Secret data.
type outcome struct {
	export string // configured exposure name; empty if none matched
	key    string
	client netip.Addr
	peer   netip.Addr
	status int
	reason string
}

func (h *Handler) serveSecret(w http.ResponseWriter, r *http.Request) {
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
	h.handleSecret(sw, r, o)
}

// handleSecret runs the request pipeline. The order of the checks decides
// what a caller can learn about the configuration:
//
//  1. Malformed path, unknown exposure, or a client outside the exposure's
//     allowedCidrs: 404, identical in every case. From outside an allow-list,
//     an existing exposure is indistinguishable from a name that does not
//     exist, so names cannot be probed.
//  2. Authentication Secret missing or malformed: 503.
//  3. Missing or wrong credentials: 401. Nothing about keys is revealed
//     before this point.
//  4. Source Secret absent: 503, whatever the key.
//  5. Key not served: 503 if listed in includeKeys (the configuration
//     promises it), otherwise 404. includeKeys and excludeKeys define which
//     keys the exposure has at all, so a filtered-out key is simply one that
//     does not exist, not a separate case.
//  6. The value, or 304 if the client already has it.
func (h *Handler) handleSecret(w http.ResponseWriter, r *http.Request, o *outcome) {
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
	name, key, ok := parseSecretPath(r.URL.EscapedPath())
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
	o.export, o.key = exp.Name, key
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
	verifier, err := auth.NewVerifier(exp.Auth.Type, authSecret.Data)
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
	value, ok := source.Data[key]
	if !ok || !exp.Keys.Exposes(key) {
		if exp.Keys.Required(key) {
			fail(http.StatusServiceUnavailable, ReasonExpectedKeyMissing)
		} else {
			fail(http.StatusNotFound, ReasonKeyNotFound)
		}
		return
	}
	o.status = writeValue(w, r, value, source.UID)
	o.reason = ReasonServed
	if o.status == http.StatusNotModified {
		o.reason = ReasonNotModified
	}
}

// parseSecretPath parses /secrets/{exposure}/{key} from the escaped path.
// Validation happens on the escaped form, and the accepted character sets
// exclude '%', so no encoded separator or dot segment can be reinterpreted.
func parseSecretPath(escaped string) (name, key string, ok bool) {
	rest, found := strings.CutPrefix(escaped, secretsPrefix)
	if !found {
		return "", "", false
	}
	name, key, found = strings.Cut(rest, "/")
	if !found || strings.Contains(key, "/") {
		return "", "", false
	}
	if exposure.ValidateName(name) != nil || exposure.ValidateKey(key) != nil {
		return "", "", false
	}
	return name, key, true
}

// ETag returns the entity tag for a Secret value: HMAC-SHA256 of the value,
// keyed with the Secret's UID.
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

// writeValue sends the raw Secret value, or 304 if the client already has it.
func writeValue(w http.ResponseWriter, r *http.Request, value []byte, uid types.UID) int {
	etag := ETag(value, uid)
	hdr := w.Header()
	hdr.Set("ETag", etag)
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	if etagMatches(r.Header.Values("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return http.StatusNotModified
	}
	hdr.Set("Content-Type", "application/octet-stream")
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
	h.observer.ObserveRequest(o.export, o.status, o.reason)

	attrs := make([]slog.Attr, 0, 9)
	if o.export != "" {
		attrs = append(attrs, slog.String("export", o.export), slog.String("key", o.key))
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
