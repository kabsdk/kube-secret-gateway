// Command kube-secret-gateway-agent synchronizes gateway exposures to local files.
//
// It runs either as a long-lived process, syncing each exposure on its own
// interval, or once and then exits, for a systemd timer or cron.
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
	"slices"
	"strings"
	"syscall"
	"time"

	"kube-secret-gateway-agent/internal/config"
	"kube-secret-gateway-agent/internal/fetch"
	"kube-secret-gateway-agent/internal/gateway"
	"kube-secret-gateway-agent/internal/metrics"
)

const appName = "kube-secret-gateway-agent"

const metricsShutdownTimeout = 5 * time.Second

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// run returns the process exit code: 0 on success, 1 if any exposure failed, 2
// for a usage or configuration error.
func run(parent context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path to the YAML configuration file")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "directory for the per-exposure ETag and stamp files")
	once := fs.Bool("once", false, "sync every selected exposure once and exit, instead of running on each exposure's interval")
	only := fs.String("exposure", "", "comma-separated exposures to sync (default: all)")
	commandTimeout := fs.Duration("command-timeout", fetch.DefaultCommandTimeout, "how long one onChangeCommand may run")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	check := fs.Bool("check", false, "validate the configuration and credentials, then exit without contacting the gateway")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s [flags]\n\nSynchronizes kube-secret-gateway exposures to local files.\n\nFlags:\n", appName)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stderr, "%s %s\n", appName, version)
		return 0
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	log, err := newLogger(stderr, level, *logFormat)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := selectExposures(cfg, *only); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Credentials are checked once at startup so that a typo in a path fails
	// immediately rather than at the first fetch, which may be hours away.
	// The values are discarded; each fetch reads them again.
	if err := checkCredentials(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *check {
		fmt.Fprintf(stderr, "%s: configuration and credentials are valid (%d exposure(s))\n", *configPath, len(cfg.Exposures))
		return 0
	}

	client, err := gateway.New(cfg.Gateway, version)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	agentMetrics, err := metrics.New(cfg.Exposures, version)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	runner, err := fetch.NewRunner(cfg, fetch.Options{
		Client:         client,
		StateDir:       *stateDir,
		Logger:         log,
		CommandTimeout: *commandTimeout,
		Observer:       agentMetrics,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version, "gateway", client.BaseURL(),
		"exposures", len(cfg.Exposures), "state_dir", *stateDir, "once", *once)

	if *once {
		if err := runner.Once(ctx); err != nil {
			return 1
		}
		return 0
	}

	listener, err := net.Listen("tcp", cfg.Metrics.ListenAddress)
	if err != nil {
		log.Error("cannot listen for metrics", "address", cfg.Metrics.ListenAddress, "error", err)
		return 1
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", agentMetrics.Handler())
	metricsServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- metricsServer.Serve(listener) }()
	log.Info("metrics listener started", "address", listener.Addr(), "path", "/metrics")

	runnerDone := make(chan struct{})
	go func() {
		runner.Serve(ctx)
		close(runnerDone)
	}()

	exitCode := 0
	select {
	case <-runnerDone:
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics listener stopped", "error", err)
			exitCode = 1
		}
		stop()
		<-runnerDone
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		log.Error("cannot stop metrics listener", "error", err)
		exitCode = 1
	}
	cancel()
	log.Info("stopped")
	return exitCode
}

// selectExposures narrows the configuration to the named exposures.
func selectExposures(cfg *config.Config, only string) error {
	if only == "" {
		return nil
	}
	wanted := strings.Split(only, ",")
	var unknown []string
	var chosen []config.Exposure
	for _, name := range wanted {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		i := slices.IndexFunc(cfg.Exposures, func(e config.Exposure) bool { return e.Name == name })
		if i < 0 {
			unknown = append(unknown, name)
			continue
		}
		if !slices.ContainsFunc(chosen, func(e config.Exposure) bool { return e.Name == name }) {
			chosen = append(chosen, cfg.Exposures[i])
		}
	}
	if len(unknown) > 0 {
		configured := make([]string, len(cfg.Exposures))
		for i, e := range cfg.Exposures {
			configured[i] = e.Name
		}
		return fmt.Errorf("no such exposure: %s (configured: %s)", strings.Join(unknown, ", "), strings.Join(configured, ", "))
	}
	if len(chosen) == 0 {
		return errors.New("-exposure selected no exposures")
	}
	cfg.Exposures = chosen
	return nil
}

// checkCredentials resolves every exposure's credentials and throws them away.
func checkCredentials(cfg *config.Config) error {
	var errs []error
	for _, e := range cfg.Exposures {
		if _, _, err := e.Auth.Resolve(e.Name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q: want debug, info, warn or error", s)
	}
}

func newLogger(w io.Writer, level slog.Level, format string) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(format) {
	case "text":
		// The default for a host tool: this usually goes to the journal,
		// which is read by people.
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q: want text or json", format)
	}
}
