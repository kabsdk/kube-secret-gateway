package server

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"kube-secret-gateway/internal/auth"
	"kube-secret-gateway/internal/exposure"
)

// MetricsOptions configures the metrics listener's handler.
type MetricsOptions struct {
	// Metrics serves the Prometheus exposition. Required.
	Metrics http.Handler
	// Ready reports application readiness for /readyz. Required.
	Ready func() bool
	// Auth, when set, protects /metrics with credentials from a watched
	// Secret, looked up through Secrets. The probes stay unauthenticated.
	// The caller verifies the Secret at startup; if it later disappears or
	// becomes malformed, /metrics fails closed with 503.
	Auth    *exposure.Auth
	Secrets SecretSource
	Logger  *slog.Logger
}

type metricsHandler struct {
	metrics http.Handler
	ready   func() bool
	auth    *exposure.Auth
	secrets SecretSource
	log     *slog.Logger
}

// NewMetricsHandler returns the handler for the metrics listener.
func NewMetricsHandler(opts MetricsOptions) (http.Handler, error) {
	if opts.Metrics == nil || opts.Ready == nil || opts.Logger == nil || (opts.Auth != nil && opts.Secrets == nil) {
		return nil, errors.New("server: incomplete metrics options")
	}
	return &metricsHandler{
		metrics: opts.Metrics,
		ready:   opts.Ready,
		auth:    opts.Auth,
		secrets: opts.Secrets,
		log:     opts.Logger,
	}, nil
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if path != "/healthz" && path != "/readyz" && path != "/metrics" {
		writeError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed)
		return
	}
	switch path {
	case "/healthz":
		probe(w, true)
	case "/readyz":
		probe(w, h.ready())
	case "/metrics":
		if h.authorize(w, r) {
			h.metrics.ServeHTTP(w, r)
		}
	}
}

// authorize applies the optional /metrics authentication with the same
// semantics as the Secret endpoints: an unusable authentication Secret is an
// operational failure (503), wrong or missing credentials are a 401.
func (h *metricsHandler) authorize(w http.ResponseWriter, r *http.Request) bool {
	if h.auth == nil {
		return true
	}
	secret := h.secrets.Secret(h.auth.SecretRef)
	if !secret.Present {
		h.log.Warn("metrics authentication Secret unavailable", "namespace", h.auth.SecretRef.Namespace, "secret", h.auth.SecretRef.Name)
		writeError(w, http.StatusServiceUnavailable)
		return false
	}
	verifier, err := auth.NewVerifier(h.auth.Type, secret.Data)
	if err != nil {
		h.log.Warn("metrics authentication Secret unusable", "namespace", h.auth.SecretRef.Namespace, "secret", h.auth.SecretRef.Name, "error", err)
		writeError(w, http.StatusServiceUnavailable)
		return false
	}
	if !verifier.Verify(r) {
		h.log.Warn("metrics request rejected: missing or invalid credentials", "remote_addr", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", verifier.Challenge())
		writeError(w, http.StatusUnauthorized)
		return false
	}
	return true
}

func probe(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "not ready\n")
		return
	}
	_, _ = io.WriteString(w, "ok\n")
}
