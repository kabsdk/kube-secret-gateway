// Command kube-secret-gateway serves explicitly configured Kubernetes Secret
// values over authenticated HTTP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	"kube-secret-gateway/internal/auth"
	"kube-secret-gateway/internal/clientip"
	"kube-secret-gateway/internal/config"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/kubernetes"
	"kube-secret-gateway/internal/metrics"
	"kube-secret-gateway/internal/resources"
	"kube-secret-gateway/internal/server"
)

const appName = "kube-secret-gateway"

const (
	// shutdownTimeout bounds how long in-flight requests may take to finish
	// after SIGTERM. It stays below Kubernetes' default 30s grace period.
	shutdownTimeout = 20 * time.Second
	// tlsReloadInterval is how often certificate files are checked for
	// renewal. The kubelet itself takes up to about a minute to update a
	// mounted Secret, and certificates are renewed well before expiry.
	tlsReloadInterval = time.Minute
	// metricsAuthStartupTimeout bounds the wait for the metrics
	// authentication Secret at startup, allowing a few retries if the API is
	// briefly unavailable.
	metricsAuthStartupTimeout = 30 * time.Second
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// run starts the gateway and blocks until SIGTERM, SIGINT or the end of
// parent, then shuts down gracefully. It returns the process exit code.
func run(parent context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path to the YAML configuration file")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file for running outside a cluster (default: in-cluster service account)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	logger, err := newLogger(stderr, level, *logFormat)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	slog.SetDefault(logger)
	// client-go logs through klog. Its verbose levels can include request
	// details, so it never logs below Info, whatever -log-level says.
	clientGoLogger, _ := newLogger(stderr, max(level, slog.LevelInfo), *logFormat)
	klog.SetSlogLogger(clientGoLogger.With("component", "client-go"))

	// The whole configuration is validated, and certificates are loaded,
	// before anything else starts.
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("cannot load configuration", "path", *configPath, "error", err)
		return 1
	}
	secretsTLS, err := loadTLS(cfg.Server.TLS)
	if err != nil {
		logger.Error("cannot load server TLS certificate", "error", err)
		return 1
	}
	metricsTLS, err := loadTLS(cfg.Metrics.TLS)
	if err != nil {
		logger.Error("cannot load metrics TLS certificate", "error", err)
		return 1
	}
	logStartup(logger, *configPath, cfg, secretsTLS)

	restConfig, err := kubernetes.RESTConfig(*kubeconfig, appName+"/"+version)
	if err != nil {
		logger.Error("cannot initialize Kubernetes client", "error", err)
		return 1
	}
	clientset, err := kubernetes.NewClientset(restConfig)
	if err != nil {
		logger.Error("cannot initialize Kubernetes client", "error", err)
		return 1
	}

	refs := exposure.ReferencedSecrets(cfg.Exposures)
	if cfg.Metrics.Auth != nil {
		refs = append(refs, cfg.Metrics.Auth.SecretRef) // deduplicated by the manager
	}
	manager := resources.NewManager(kubernetes.NewSecretClient(clientset), refs, resources.Options{
		ReconcileInterval: cfg.ReconcileInterval,
		Logger:            logger.With("component", "resources"),
	})
	m, err := metrics.New(cfg.Exposures, manager)
	if err != nil {
		logger.Error("cannot register metrics", "error", err)
		return 1
	}

	httpLogger := logger.With("component", "http")
	secretsHandler, err := server.New(server.Options{
		Exposures: cfg.Exposures,
		Secrets:   manager,
		ClientIP:  clientip.NewResolver(cfg.Server.TrustedProxies),
		Observer:  m,
		Logger:    httpLogger,
	})
	if err != nil {
		logger.Error("cannot create HTTP handler", "error", err)
		return 1
	}
	var shuttingDown atomic.Bool
	metricsHandler, err := server.NewMetricsHandler(server.MetricsOptions{
		Metrics: m.Handler(),
		Ready:   func() bool { return !shuttingDown.Load() && manager.Initialized() },
		Auth:    cfg.Metrics.Auth,
		Secrets: manager,
		Logger:  httpLogger,
	})
	if err != nil {
		logger.Error("cannot create metrics handler", "error", err)
		return 1
	}

	secretsListener, err := net.Listen("tcp", cfg.Server.ListenAddress)
	if err != nil {
		logger.Error("cannot listen", "address", cfg.Server.ListenAddress, "error", err)
		return 1
	}
	defer secretsListener.Close()
	metricsListener, err := net.Listen("tcp", cfg.Metrics.ListenAddress)
	if err != nil {
		logger.Error("cannot listen", "address", cfg.Metrics.ListenAddress, "error", err)
		return 1
	}
	defer metricsListener.Close()

	ctx, stopSignals := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()

	// Watchers and certificate reloaders get their own context so they keep
	// running until in-flight HTTP requests have drained.
	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	manager.Start(background)
	go logInitialSync(background, logger, manager)
	for _, r := range []*server.CertificateReloader{secretsTLS, metricsTLS} {
		if r != nil {
			go r.Run(background, tlsReloadInterval, httpLogger)
		}
	}

	// Unlike exposure Secrets, which may legitimately appear later, the
	// metrics credentials are part of the gateway's own setup: a missing or
	// malformed Secret at startup is a deployment error, and failing here
	// stops a bad rollout while the previous pods keep serving.
	if a := cfg.Metrics.Auth; a != nil {
		if err := checkMetricsAuth(ctx, manager, *a); err != nil {
			logger.Error("metrics authentication is not usable",
				"namespace", a.SecretRef.Namespace, "secret", a.SecretRef.Name, "error", err)
			stopBackground()
			manager.Wait()
			return 1
		}
	}

	secretsServer := newServer(secretsHandler, secretsTLS, httpLogger)
	metricsServer := newServer(metricsHandler, metricsTLS, httpLogger)
	serveErr := make(chan error, 2)
	go func() { serveErr <- serve(secretsServer, secretsListener) }()
	go func() { serveErr <- serve(metricsServer, metricsListener) }()
	logger.Info("listening",
		"secrets_address", secretsListener.Addr().String(), "secrets_tls", secretsTLS != nil,
		"metrics_address", metricsListener.Addr().String(), "metrics_tls", metricsTLS != nil,
		"metrics_auth", cfg.Metrics.Auth != nil, "watched_secrets", len(refs))

	exitCode := 0
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-serveErr:
		logger.Error("HTTP server failed", "error", err)
		exitCode = 1
	}
	// A second signal now terminates immediately.
	stopSignals()

	shuttingDown.Store(true)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	// Drain Secret requests first; the metrics listener keeps answering
	// probes until then.
	for _, srv := range []*http.Server{secretsServer, metricsServer} {
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("HTTP shutdown incomplete", "error", err)
			exitCode = 1
		}
	}
	stopBackground()
	manager.Wait()
	logger.Info("stopped")
	return exitCode
}

// checkMetricsAuth waits until the metrics authentication Secret has been
// read and verifies that it holds usable credentials. After startup the
// Secret stays watched, so credentials can be rotated without a restart.
func checkMetricsAuth(ctx context.Context, manager *resources.Manager, a exposure.Auth) error {
	ctx, cancel := context.WithTimeout(ctx, metricsAuthStartupTimeout)
	defer cancel()
	if err := manager.WaitSynced(ctx, a.SecretRef); err != nil {
		return fmt.Errorf("the Secret could not be read within %s; check RBAC and API server connectivity", metricsAuthStartupTimeout)
	}
	s := manager.Secret(a.SecretRef)
	if !s.Present {
		return errors.New("the Secret does not exist")
	}
	_, err := auth.NewVerifier(a.Type, s.Data)
	return err
}

func loadTLS(files *config.TLS) (*server.CertificateReloader, error) {
	if files == nil {
		return nil, nil
	}
	return server.NewCertificateReloader(files.CertFile, files.KeyFile)
}

func newServer(h http.Handler, certs *server.CertificateReloader, log *slog.Logger) *http.Server {
	srv := server.NewHTTPServer(h, log)
	if certs != nil {
		srv.TLSConfig = server.TLSConfig(certs)
	}
	return srv
}

func serve(srv *http.Server, l net.Listener) error {
	if srv.TLSConfig != nil {
		return srv.ServeTLS(l, "", "")
	}
	return srv.Serve(l)
}

func logStartup(logger *slog.Logger, path string, cfg *config.Config, secretsTLS *server.CertificateReloader) {
	logger.Info("starting", "version", version, "config", path,
		"exposures", len(cfg.Exposures), "reconcile_interval", cfg.ReconcileInterval.String(),
		"trusted_proxies", len(cfg.Server.TrustedProxies))
	for i := range cfg.Exposures {
		e := &cfg.Exposures[i]
		logger.Info("exposure configured", "exposure", e.Name,
			"namespace", e.Source.Namespace, "secret", e.Source.Name,
			"auth_type", string(e.Auth.Type), "auth_namespace", e.Auth.SecretRef.Namespace, "auth_secret", e.Auth.SecretRef.Name,
			"allowed_cidrs", len(e.AllowedCIDRs), "required_keys", e.Keys.RequiredKeys())
	}
	if secretsTLS == nil {
		logger.Warn("serving Secrets over plain HTTP: credentials and Secret values cross the network unencrypted " +
			"unless the pod network encrypts traffic; configure server.tls to prevent this")
	} else {
		logger.Info("serving Secrets over TLS", "cert_file", cfg.Server.TLS.CertFile, "not_after", secretsTLS.NotAfter())
	}
}

func logInitialSync(ctx context.Context, logger *slog.Logger, manager *resources.Manager) {
	start := time.Now()
	if manager.WaitInitialized(ctx) != nil {
		return
	}
	var present, absent, failed int
	for _, st := range manager.Statuses() {
		switch {
		case !st.Synced:
			failed++
		case st.Present:
			present++
		default:
			absent++
		}
	}
	logger.Info("initial synchronization complete", "duration", time.Since(start),
		"present", present, "absent", absent, "failed", failed)
}

func parseLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("invalid -log-level %q: use debug, info, warn or error", s)
	}
	return level, nil
}

func newLogger(w io.Writer, level slog.Level, format string) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: level}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid -log-format %q: use json or text", format)
	}
}
