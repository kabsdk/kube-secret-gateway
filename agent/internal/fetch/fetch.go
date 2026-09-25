// Package fetch installs exposures and keeps them up to date.
//
// One request returns every value in an exposure from one version of its
// Kubernetes Secret, so a certificate and its private key are never downloaded
// from different versions.
//
// Within an exposure the same care is taken locally. Every file is written to a
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

// Observer receives one event after every exposure synchronization attempt.
// Implementations must be safe for concurrent calls from different exposures.
type Observer interface {
	ObserveSync(exposure string, changed bool, err error, duration time.Duration)
}

type discardObserver struct{}

func (discardObserver) ObserveSync(string, bool, error, time.Duration) {}

// Runner syncs the exposures of one configuration.
type Runner struct {
	cfg      *config.Config
	client   *gateway.Client
	stateDir string
	log      *slog.Logger
	timeout  time.Duration
	observer Observer
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
	}, nil
}

// Once syncs every exposure in turn and returns the problems it hit. Every
// exposure is attempted even if an earlier one failed, so one broken exposure
// does not hide the state of the others.
func (r *Runner) Once(ctx context.Context) error {
	var errs []error
	for _, e := range r.cfg.Exposures {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if _, err := r.Sync(ctx, e); err != nil {
			r.log.Error("sync failed", "exposure", e.Name, "error", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Serve syncs each exposure on its own interval until ctx is cancelled. A
// failure is logged and retried on its next tick; one unreachable exposure
// never stops the others. Serve returns when every exposure has stopped.
func (r *Runner) Serve(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range r.cfg.Exposures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.serveExposure(ctx, e)
		}()
	}
	wg.Wait()
}

func (r *Runner) serveExposure(ctx context.Context, e config.Exposure) {
	log := r.log.With("exposure", e.Name)
	log.Info("watching", "interval", e.Interval, "targets", len(e.Targets))
	for {
		if _, err := r.Sync(ctx, e); err != nil && ctx.Err() == nil {
			log.Error("sync failed, will retry", "error", err, "retry_in", e.Interval)
		}
		// Jitter spreads the polling of many hosts that were configured and
		// started together, so they do not all ask at the same instant.
		wait := e.Interval
		if window := e.Interval / 10; window > 0 {
			wait = e.Interval - window/2 + rand.N(window)
		}
		select {
		case <-ctx.Done():
			log.Info("stopped")
			return
		case <-time.After(wait):
		}
	}
}

// Sync fetches one exposure and installs its targets if anything changed. It reports
// whether files were written.
func (r *Runner) Sync(ctx context.Context, e config.Exposure) (changed bool, err error) {
	started := time.Now()
	defer func() { r.observer.ObserveSync(e.Name, changed, err, time.Since(started)) }()

	log := r.log.With("exposure", e.Name)

	username, password, err := e.Auth.Resolve(e.Name)
	if err != nil {
		return false, err
	}

	etag, err := r.currentETag(e)
	if err != nil {
		return false, err
	}

	result, err := r.client.Fetch(ctx, e.Name, etag, username, password)
	switch {
	case errors.Is(err, gateway.ErrNotModified):
		log.Debug("unchanged")
		return false, nil
	case err != nil:
		return false, err
	}

	// Every target key must be in the response before any files are changed.
	var missing []string
	for _, target := range e.Targets {
		if _, ok := result.Values[target.Key]; !ok {
			missing = append(missing, target.Key)
		}
	}
	if len(missing) > 0 {
		return false, fmt.Errorf("exposure %q does not contain target key(s) %s (it contains %s)",
			e.Name, strings.Join(missing, ", "), strings.Join(slices.Sorted(maps.Keys(result.Values)), ", "))
	}

	if err := install(e.Targets, result.Values); err != nil {
		return false, fmt.Errorf("exposure %q: %w", e.Name, err)
	}
	if err := touchStamp(r.stampPath(e)); err != nil {
		return true, fmt.Errorf("exposure %q: writing the stamp file: %w", e.Name, err)
	}
	log.Info("installed", "targets", len(e.Targets))

	if len(e.OnChangeCommand) > 0 {
		if err := r.runCommand(ctx, e); err != nil {
			return true, err
		}
	}
	// The ETag commits the complete sync, including onChangeCommand. Keeping
	// the old tag when the command fails makes the next poll fetch and retry
	// instead of accepting a 304 and silently leaving the consumer stale.
	if err := writeFile(r.etagPath(e), []byte(result.ETag+"\n"), 0o600); err != nil {
		return true, fmt.Errorf("exposure %q: recording the ETag: %w", e.Name, err)
	}

	return true, nil
}

// currentETag is the stored tag, or "" to fetch unconditionally. The tag
// describes files on disk, so it is only trusted while every one of them is
// present with the mode the configuration asks for. A deleted or chmod-ed file
// therefore reinstalls every target rather than being left alone.
func (r *Runner) currentETag(e config.Exposure) (string, error) {
	for _, f := range e.Targets {
		info, err := os.Stat(f.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", nil
		case err != nil:
			return "", fmt.Errorf("exposure %q: %s: %w", e.Name, f.Path, err)
		case info.Mode().Perm() != f.Mode:
			return "", nil
		}
	}
	data, err := os.ReadFile(r.etagPath(e))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("exposure %q: reading the stored ETag: %w", e.Name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (r *Runner) etagPath(e config.Exposure) string {
	return filepath.Join(r.stateDir, e.Name+".etag")
}

// stampPath is touched after every change. It gives systemd a single file to
// watch with a .path unit, which is the safe trigger: watching the installed
// files themselves fires once per file, so a reload can run between the
// certificate and the key.
func (r *Runner) stampPath(e config.Exposure) string {
	return filepath.Join(r.stateDir, e.Name+".stamp")
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

// install writes every target, then renames them into place. Nothing
// is renamed until every temporary file has been written and flushed. Each
// rename is atomic, but the sequence of renames is not a filesystem
// transaction; the caller commits the ETag only after the sequence completes.
func install(files []config.Target, values map[string][]byte) error {
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

// runCommand runs an exposure's onChangeCommand without a shell. The command and
// its arguments come from the configuration exactly as written, so the usual
// quoting and word-splitting surprises cannot happen.
func (r *Runner) runCommand(ctx context.Context, e config.Exposure) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.OnChangeCommand[0], e.OnChangeCommand[1:]...)
	start := time.Now()
	output, err := cmd.CombinedOutput()
	attrs := []any{"exposure", e.Name, "command", e.OnChangeCommand, "duration", time.Since(start)}
	if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
		attrs = append(attrs, "output", truncate(trimmed, maxCommandOutput))
	}
	if err != nil {
		r.log.Error("onChangeCommand failed", append(attrs, "error", err)...)
		return fmt.Errorf("exposure %q: onChangeCommand %v: %w", e.Name, e.OnChangeCommand, err)
	}
	r.log.Info("onChangeCommand ran", attrs...)
	return nil
}

func dirs(files []config.Target) []string {
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
