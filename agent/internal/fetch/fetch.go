// Package fetch installs bundles and keeps them up to date.
//
// One bundle is one exposure, so one HTTP request returns every value it
// contains from one version of the Secret. That is the whole reason a bundle
// exists: a certificate and its private key are never downloaded from two
// different versions.
//
// Within a bundle the same care is taken locally. Every file is written to a
// temporary file next to its destination and flushed to disk first; only then
// are the temporary files renamed into place, one rename per file, with no
// download or fsync in between. A crash can therefore leave at most a few
// renames undone, and never a half-written file.
//
// The stored ETag is written after the files and onChangeCommand. A crash or
// command failure leaves a stale tag, so the next run fetches, installs and
// reloads again. The reverse order could record a completed sync that never
// reached the consumer.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"kube-secret-gateway-agent/internal/config"
	"kube-secret-gateway-agent/internal/gateway"
)

// DefaultCommandTimeout bounds one onChangeCommand.
const DefaultCommandTimeout = 2 * time.Minute

// maxCommandOutput is how much of a command's output is logged.
const maxCommandOutput = 4 << 10

// Options configures a Runner. Client, StateDir and Logger are required.
type Options struct {
	Client         *gateway.Client
	StateDir       string
	Logger         *slog.Logger
	CommandTimeout time.Duration
	Observer       Observer
}

// Observer receives one event after every bundle synchronization attempt.
// Implementations must be safe for concurrent calls from different bundles.
type Observer interface {
	ObserveSync(bundle string, changed bool, err error, duration time.Duration)
}

type discardObserver struct{}

func (discardObserver) ObserveSync(string, bool, error, time.Duration) {}

// Runner syncs the bundles of one configuration.
type Runner struct {
	cfg      *config.Config
	client   *gateway.Client
	stateDir string
	log      *slog.Logger
	timeout  time.Duration
	observer Observer
	// env is the environment for onChangeCommand: this process's, without any
	// variable that holds a password.
	env []string
}

// NewRunner returns a Runner. The state directory is created if it is missing.
func NewRunner(cfg *config.Config, opts Options) (*Runner, error) {
	if cfg == nil || opts.Client == nil || opts.StateDir == "" || opts.Logger == nil {
		return nil, errors.New("fetch: incomplete options")
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	timeout := opts.CommandTimeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	observer := opts.Observer
	if observer == nil {
		observer = discardObserver{}
	}
	return &Runner{
		cfg:      cfg,
		client:   opts.Client,
		stateDir: opts.StateDir,
		log:      opts.Logger,
		timeout:  timeout,
		observer: observer,
		env:      scrubbed(os.Environ(), cfg.PasswordEnvNames()),
	}, nil
}

// scrubbed removes the named variables. A command run after a change has no
// business seeing a password, and would pass it on to anything it starts.
func scrubbed(env, remove []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(remove, name) {
			out = append(out, kv)
		}
	}
	return out
}

// Once syncs every bundle in turn and returns the problems it hit. Every
// bundle is attempted even if an earlier one failed, so one broken exposure
// does not hide the state of the others.
func (r *Runner) Once(ctx context.Context) error {
	var errs []error
	for _, b := range r.cfg.Bundles {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if _, err := r.Sync(ctx, b); err != nil {
			r.log.Error("sync failed", "bundle", b.Name, "error", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Serve syncs each bundle on its own interval until ctx is cancelled. A bundle
// that fails is logged and retried on its next tick: one unreachable exposure
// never stops the others. Serve returns when every bundle has stopped.
func (r *Runner) Serve(ctx context.Context) {
	var wg sync.WaitGroup
	for _, b := range r.cfg.Bundles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.serveBundle(ctx, b)
		}()
	}
	wg.Wait()
}

func (r *Runner) serveBundle(ctx context.Context, b config.Bundle) {
	log := r.log.With("bundle", b.Name)
	log.Info("watching", "exposure", b.Exposure, "interval", b.Interval, "files", len(b.Files))
	for {
		if _, err := r.Sync(ctx, b); err != nil && ctx.Err() == nil {
			log.Error("sync failed, will retry", "error", err, "retry_in", b.Interval)
		}
		// Jitter spreads the polling of many hosts that were configured and
		// started together, so they do not all ask at the same instant.
		wait := b.Interval
		if window := b.Interval / 10; window > 0 {
			wait = b.Interval - window/2 + rand.N(window)
		}
		select {
		case <-ctx.Done():
			log.Info("stopped")
			return
		case <-time.After(wait):
		}
	}
}

// Sync fetches one bundle and installs it if anything changed. It reports
// whether files were written.
func (r *Runner) Sync(ctx context.Context, b config.Bundle) (changed bool, err error) {
	started := time.Now()
	defer func() { r.observer.ObserveSync(b.Name, changed, err, time.Since(started)) }()

	log := r.log.With("bundle", b.Name)

	username, password, err := r.cfg.Credentials(b).Resolve()
	if err != nil {
		return false, err
	}

	etag, err := r.currentETag(b)
	if err != nil {
		return false, err
	}

	bundle, err := r.client.Fetch(ctx, b.Exposure, etag, username, password)
	switch {
	case errors.Is(err, gateway.ErrNotModified):
		log.Debug("unchanged")
		return false, nil
	case err != nil:
		return false, err
	}

	// Every configured key must be in the response. A bundle contains what
	// the exposure serves, which includeKeys and excludeKeys decide, so a
	// missing key is a configuration mismatch, not a transient failure.
	var missing []string
	for _, f := range b.Files {
		if _, ok := bundle.Values[f.Key]; !ok {
			missing = append(missing, f.Key)
		}
	}
	if len(missing) > 0 {
		return false, fmt.Errorf("bundle %q: exposure %q does not serve %s (it serves %s)",
			b.Name, b.Exposure, strings.Join(missing, ", "), strings.Join(slices.Sorted(maps.Keys(bundle.Values)), ", "))
	}

	if err := install(b.Files, bundle.Values); err != nil {
		return false, fmt.Errorf("bundle %q: %w", b.Name, err)
	}
	if err := touchStamp(r.stampPath(b)); err != nil {
		return true, fmt.Errorf("bundle %q: writing the stamp file: %w", b.Name, err)
	}
	log.Info("installed", "exposure", b.Exposure, "files", len(b.Files))

	if len(b.OnChangeCommand) > 0 {
		if err := r.runCommand(ctx, b); err != nil {
			return true, err
		}
	}
	// The ETag commits the complete sync, including onChangeCommand. Keeping
	// the old tag when the command fails makes the next poll fetch and retry
	// instead of accepting a 304 and silently leaving the consumer stale.
	if err := writeFile(r.etagPath(b), []byte(bundle.ETag+"\n"), 0o600); err != nil {
		return true, fmt.Errorf("bundle %q: recording the ETag: %w", b.Name, err)
	}

	return true, nil
}

// currentETag is the stored tag, or "" to fetch unconditionally. The tag
// describes files on disk, so it is only trusted while every one of them is
// present with the mode the configuration asks for. A deleted or chmod-ed file
// therefore reinstalls the whole bundle rather than being left alone.
func (r *Runner) currentETag(b config.Bundle) (string, error) {
	for _, f := range b.Files {
		info, err := os.Stat(f.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", nil
		case err != nil:
			return "", fmt.Errorf("bundle %q: %s: %w", b.Name, f.Path, err)
		case info.Mode().Perm() != f.Mode:
			return "", nil
		}
	}
	data, err := os.ReadFile(r.etagPath(b))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("bundle %q: reading the stored ETag: %w", b.Name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (r *Runner) etagPath(b config.Bundle) string {
	return filepath.Join(r.stateDir, b.Name+".etag")
}

// stampPath is touched after every change. It gives systemd a single file to
// watch with a .path unit, which is the safe trigger: watching the installed
// files themselves fires once per file, so a reload can run between the
// certificate and the key.
func (r *Runner) stampPath(b config.Bundle) string {
	return filepath.Join(r.stateDir, b.Name+".stamp")
}

// touchStamp writes the stamp file in place rather than renaming one over it.
// systemd's PathChanged= waits for a file to be closed after writing, which a
// rename into place does not do, so an atomic replacement would never trigger
// the .path unit this file exists for.
func touchStamp(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(time.Now().UTC().Format(time.RFC3339Nano) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// install writes every file of a bundle, then renames them into place. Nothing
// is renamed until every temporary file has been written and flushed. Each
// rename is atomic, but the sequence of renames is not a filesystem
// transaction; the caller commits the ETag only after the sequence completes.
func install(files []config.File, values map[string][]byte) error {
	temps := make([]string, 0, len(files))
	defer func() {
		// Anything still listed here was not renamed: remove it.
		for _, tmp := range temps {
			if tmp != "" {
				_ = os.Remove(tmp)
			}
		}
	}()

	for _, f := range files {
		tmp, err := writeTemp(f.Path, values[f.Key], f.Mode)
		if err != nil {
			return err
		}
		temps = append(temps, tmp)
	}
	for i, f := range files {
		if err := os.Rename(temps[i], f.Path); err != nil {
			return fmt.Errorf("installing %s: %w", f.Path, err)
		}
		temps[i] = "" // renamed; os.Remove("") fails harmlessly
	}
	// Flush the renames themselves, so the set survives a power loss.
	for _, dir := range dirs(files) {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

// writeTemp writes data to a new file in the destination's directory and
// returns its path. The file is created with the destination's mode, never
// wider, so the value is not briefly world-readable.
func writeTemp(path string, data []byte, mode fs.FileMode) (string, error) {
	dir, base := filepath.Split(path)
	f, err := os.CreateTemp(dir, "."+base+".tmp")
	if err != nil {
		return "", fmt.Errorf("preparing %s: %w", path, err)
	}
	tmp := f.Name()
	err = func() error {
		// CreateTemp makes the file 0600; Chmod applies the configured mode
		// without the umask interfering.
		if err := f.Chmod(mode); err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return tmp, nil
}

// writeFile replaces path atomically. It is used for the small state files,
// which are not Secret values.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	tmp, err := writeTemp(path, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// runCommand runs a bundle's onChangeCommand without a shell. The command and
// its arguments come from the configuration exactly as written, so the usual
// quoting and word-splitting surprises cannot happen.
func (r *Runner) runCommand(ctx context.Context, b config.Bundle) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, b.OnChangeCommand[0], b.OnChangeCommand[1:]...)
	cmd.Env = r.env
	start := time.Now()
	output, err := cmd.CombinedOutput()
	attrs := []any{"bundle", b.Name, "command", b.OnChangeCommand, "duration", time.Since(start)}
	if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
		attrs = append(attrs, "output", truncate(trimmed, maxCommandOutput))
	}
	if err != nil {
		r.log.Error("onChangeCommand failed", append(attrs, "error", err)...)
		return fmt.Errorf("bundle %q: onChangeCommand %v: %w", b.Name, b.OnChangeCommand, err)
	}
	r.log.Info("onChangeCommand ran", attrs...)
	return nil
}

func dirs(files []config.File) []string {
	var out []string
	for _, f := range files {
		if dir := filepath.Dir(f.Path); !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
