// Command kube-secret-gateway-agent synchronizes gateway bundles to local files.
//
// It runs either as a long-lived process, syncing each bundle on its own
// interval, or once and then exits, for a systemd timer or cron.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"kube-secret-gateway-agent/internal/config"
	"kube-secret-gateway-agent/internal/fetch"
	"kube-secret-gateway-agent/internal/gateway"
)

const appName = "kube-secret-gateway-agent"

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// run returns the process exit code: 0 on success, 1 if any bundle failed, 2
// for a usage or configuration error.
func run(parent context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path to the YAML configuration file")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "directory for the per-bundle ETag and stamp files")
	once := fs.Bool("once", false, "sync every selected bundle once and exit, instead of running on each bundle's interval")
	only := fs.String("bundle", "", "comma-separated bundles to sync (default: all)")
	commandTimeout := fs.Duration("command-timeout", fetch.DefaultCommandTimeout, "how long one onChangeCommand may run")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	check := fs.Bool("check", false, "validate the configuration and credentials, then exit without contacting the gateway")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s [flags]\n\nSynchronizes kube-secret-gateway bundles to local files.\n\nFlags:\n", appName)
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
	if err := selectBundles(cfg, *only); err != nil {
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
		fmt.Fprintf(stderr, "%s: configuration and credentials are valid (%d bundle(s))\n", *configPath, len(cfg.Bundles))
		return 0
	}

	client, err := gateway.New(cfg.Gateway, version)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	runner, err := fetch.NewRunner(cfg, fetch.Options{
		Client:         client,
		StateDir:       *stateDir,
		Logger:         log,
		CommandTimeout: *commandTimeout,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version, "gateway", client.BaseURL(),
		"bundles", len(cfg.Bundles), "state_dir", *stateDir, "once", *once)

	if *once {
		if err := runner.Once(ctx); err != nil {
			return 1
		}
		return 0
	}
	runner.Serve(ctx)
	log.Info("stopped")
	return 0
}

// selectBundles narrows the configuration to the named bundles.
func selectBundles(cfg *config.Config, only string) error {
	if only == "" {
		return nil
	}
	wanted := strings.Split(only, ",")
	var unknown []string
	var chosen []config.Bundle
	for _, name := range wanted {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		i := slices.IndexFunc(cfg.Bundles, func(b config.Bundle) bool { return b.Name == name })
		if i < 0 {
			unknown = append(unknown, name)
			continue
		}
		if !slices.ContainsFunc(chosen, func(b config.Bundle) bool { return b.Name == name }) {
			chosen = append(chosen, cfg.Bundles[i])
		}
	}
	if len(unknown) > 0 {
		configured := make([]string, len(cfg.Bundles))
		for i, b := range cfg.Bundles {
			configured[i] = b.Name
		}
		return fmt.Errorf("no such bundle: %s (configured: %s)", strings.Join(unknown, ", "), strings.Join(configured, ", "))
	}
	if len(chosen) == 0 {
		return errors.New("-bundle selected no bundles")
	}
	cfg.Bundles = chosen
	return nil
}

// checkCredentials resolves every bundle's credentials and throws them away.
func checkCredentials(cfg *config.Config) error {
	var errs []error
	seen := make(map[string]struct{})
	for _, b := range cfg.Bundles {
		if _, done := seen[b.Exposure]; done {
			continue
		}
		seen[b.Exposure] = struct{}{}
		if _, _, err := cfg.Credentials(b).Resolve(); err != nil {
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
