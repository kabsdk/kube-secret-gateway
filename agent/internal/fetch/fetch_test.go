package fetch_test

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway-agent/internal/config"
	"kube-secret-gateway-agent/internal/fetch"
	"kube-secret-gateway-agent/internal/gateway"
	"kube-secret-gateway-agent/internal/gwtest"
)

const (
	certV1 = "-----BEGIN CERTIFICATE-----\nV1\n-----END CERTIFICATE-----\n"
	keyV1  = "-----BEGIN PRIVATE KEY-----\nV1\n-----END PRIVATE KEY-----\n"
	certV2 = "-----BEGIN CERTIFICATE-----\nV2\n-----END CERTIFICATE-----\n"
	keyV2  = "-----BEGIN PRIVATE KEY-----\nV2\n-----END PRIVATE KEY-----\n"
)

type harness struct {
	t        *testing.T
	gw       *gwtest.Gateway
	cfg      *config.Config
	runner   *fetch.Runner
	dir      string // installed files
	stateDir string
	exposure config.Exposure
	// marker is appended to by the default onChangeCommand.
	marker string
	logs   *strings.Builder
}

// newHarness starts a fake gateway serving one exposure with tls.crt and
// tls.key, and a runner configured to install both.
func newHarness(t *testing.T, extra ...string) *harness {
	t.Helper()
	h := &harness{t: t, logs: &strings.Builder{}}
	h.gw = gwtest.New()
	t.Cleanup(h.gw.Close)
	h.gw.Set("my-cert", gwtest.Exposure{
		Username: "fetcher",
		Password: "correct horse battery staple",
		Values:   map[string][]byte{"tls.crt": []byte(certV1), "tls.key": []byte(keyV1), "ca.crt": []byte("CA")},
	})

	root := t.TempDir()
	h.dir = filepath.Join(root, "ssl")
	if err := os.MkdirAll(h.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.stateDir = filepath.Join(root, "state")
	h.marker = filepath.Join(root, "reloads")

	passwordFile := filepath.Join(root, "password")
	if err := os.WriteFile(passwordFile, []byte("correct horse battery staple"), 0o600); err != nil {
		t.Fatal(err)
	}

	yaml := fmt.Sprintf(`
gateway:
  url: %s
exposures:
  - name: my-cert
    auth:
      username: fetcher
      passwordFile: %s
    interval: 30s
    onChangeCommand: [sh, -c, "echo ran >> %s"]
    targets:
      - key: tls.crt
        path: %s/tls.crt
        mode: "0644"
      - key: tls.key
        path: %s/tls.key
%s`, h.gw.URL(), passwordFile, h.marker, h.dir, h.dir, strings.Join(extra, "\n"))

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	h.cfg = cfg
	h.exposure = cfg.Exposures[0]

	client, err := gateway.New(cfg.Gateway, "test")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.runner, err = fetch.NewRunner(cfg, fetch.Options{Client: client, StateDir: h.stateDir, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) sync() (bool, error) {
	h.t.Helper()
	return h.runner.Sync(context.Background(), h.exposure)
}

func (h *harness) mustSync(wantChanged bool) {
	h.t.Helper()
	changed, err := h.sync()
	if err != nil {
		h.t.Fatalf("sync: %v", err)
	}
	if changed != wantChanged {
		h.t.Fatalf("changed = %v, want %v", changed, wantChanged)
	}
}

func (h *harness) read(name string) string {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, name))
	if err != nil {
		h.t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

func (h *harness) reloads() int {
	h.t.Helper()
	data, err := os.ReadFile(h.marker)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.Count(string(data), "ran")
}

func (h *harness) mode(name string) fs.FileMode {
	h.t.Helper()
	info, err := os.Stat(filepath.Join(h.dir, name))
	if err != nil {
		h.t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestColdInstall(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)

	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q", got)
	}
	if got := h.read("tls.key"); got != keyV1 {
		t.Fatalf("tls.key = %q", got)
	}
	// The configured mode is applied; the default is owner-only.
	if got := h.mode("tls.crt"); got != 0o644 {
		t.Fatalf("tls.crt mode = %o, want 644", got)
	}
	if got := h.mode("tls.key"); got != 0o600 {
		t.Fatalf("tls.key mode = %o, want 600", got)
	}
	// ca.crt is served by the exposure but not configured, so it is not
	// installed: targets select the local subset, but the client received the
	// complete exposure.
	if _, err := os.Stat(filepath.Join(h.dir, "ca.crt")); !os.IsNotExist(err) {
		t.Fatal("installed a key that the configuration does not list")
	}
	if got := h.reloads(); got != 1 {
		t.Fatalf("onChangeCommand ran %d times, want 1", got)
	}
	for _, name := range []string{"my-cert.etag", "my-cert.stamp"} {
		if _, err := os.Stat(filepath.Join(h.stateDir, name)); err != nil {
			t.Fatalf("state file %s: %v", name, err)
		}
	}
	etag, err := os.ReadFile(filepath.Join(h.stateDir, "my-cert.etag"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(etag)) != h.gw.ETag("my-cert") {
		t.Fatalf("stored ETag = %q, gateway says %q", etag, h.gw.ETag("my-cert"))
	}
}

func TestUnchangedExposureInstallsNothing(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	before, err := os.Stat(filepath.Join(h.dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}

	for range 3 {
		h.mustSync(false)
	}
	after, err := os.Stat(filepath.Join(h.dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("an unchanged exposure rewrote the file")
	}
	if got := h.reloads(); got != 1 {
		t.Fatalf("onChangeCommand ran %d times, want 1", got)
	}
	total, notModified := h.gw.Requests()
	if notModified != 3 || total != 4 {
		t.Fatalf("gateway saw %d requests, %d of them 304; want 4 and 3", total, notModified)
	}
}

// One request returns one exposure snapshot, so the certificate and key are
// always from the same version of the Secret.
func TestRotationInstallsTheWholeSet(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)

	h.gw.Rotate("my-cert", map[string][]byte{"tls.crt": []byte(certV2), "tls.key": []byte(keyV2)})
	h.mustSync(true)

	if got := h.read("tls.crt"); got != certV2 {
		t.Fatalf("tls.crt = %q, want the rotated certificate", got)
	}
	if got := h.read("tls.key"); got != keyV2 {
		t.Fatalf("tls.key = %q, want the rotated key", got)
	}
	if got := h.reloads(); got != 2 {
		t.Fatalf("onChangeCommand ran %d times, want 2", got)
	}
	h.mustSync(false)
}

// A change to one exposure key changes the tag of the complete snapshot, so
// the client reinstalls both targets and they stay from the same version.
func TestChangeToOneKeyRefreshesTheExposure(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	h.gw.Rotate("my-cert", map[string][]byte{"tls.key": []byte(keyV2)})
	h.mustSync(true)
	if got := h.read("tls.key"); got != keyV2 {
		t.Fatalf("tls.key = %q", got)
	}
	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q, want it rewritten from the same version", got)
	}
}

// A returned key without a local target still changes the exposure ETag.
func TestUntargetedKeyStillChangesTheTag(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	h.gw.Rotate("my-cert", map[string][]byte{"extra": []byte("x")})
	// The exposure's ETag covers everything it serves, so this is a
	// change: the client refetches and rewrites the same bytes. That costs one
	// download and is the price of a single tag for the set.
	h.mustSync(true)
	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q", got)
	}
	h.mustSync(false)
}

func TestDeletedFileIsReinstalled(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	if err := os.Remove(filepath.Join(h.dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	// The stored ETag describes files on disk. One of them is gone, so it is
	// not trusted and the complete exposure is fetched again.
	h.mustSync(true)
	if got := h.read("tls.key"); got != keyV1 {
		t.Fatalf("tls.key = %q", got)
	}
}

func TestChangedModeIsRestored(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	if err := os.Chmod(filepath.Join(h.dir, "tls.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustSync(true)
	if got := h.mode("tls.key"); got != 0o600 {
		t.Fatalf("tls.key mode = %o after resync, want 600", got)
	}
}

func TestMissingConfiguredKeyIsAnError(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	h.gw.Remove("my-cert", "tls.key")

	_, err := h.sync()
	if err == nil {
		t.Fatal("an exposure without a configured target key must fail")
	}
	for _, want := range []string{"tls.key", "my-cert"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	// Nothing was installed, so the previous, consistent set is still there.
	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q, want the previous version", got)
	}
	if got := h.read("tls.key"); got != keyV1 {
		t.Fatalf("tls.key = %q, want the previous version", got)
	}
	if got := h.reloads(); got != 1 {
		t.Fatalf("onChangeCommand ran %d times, want 1", got)
	}
}

func TestGatewayErrorsLeaveFilesAlone(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)

	for _, tc := range []struct {
		status int
		want   string
	}{
		{503, "503"},
		{404, "404"},
		{401, "401"},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			h.gw.SetStatus("my-cert", tc.status)
			defer h.gw.SetStatus("my-cert", 0)
			_, err := h.sync()
			if err == nil {
				t.Fatalf("status %d did not produce an error", tc.status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %s", err, tc.want)
			}
			if got := h.read("tls.crt"); got != certV1 {
				t.Fatal("a failed fetch changed an installed file")
			}
		})
	}
	// Service resumes without intervention.
	h.mustSync(false)
}

func TestWrongPasswordIsReported(t *testing.T) {
	h := newHarness(t)
	// Rewrite the password file to something wrong: credentials are read per
	// fetch, so no restart is needed for this to take effect.
	passwordFile := h.exposure.Auth.PasswordFile
	if err := os.WriteFile(passwordFile, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := h.sync()
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want a 401", err)
	}
}

func TestCredentialsAreRereadEachFetch(t *testing.T) {
	h := newHarness(t)
	passwordFile := h.exposure.Auth.PasswordFile
	if err := os.WriteFile(passwordFile, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.sync(); err == nil {
		t.Fatal("expected a 401")
	}
	// Rotating the credentials file is enough; the process keeps running.
	if err := os.WriteFile(passwordFile, []byte("correct horse battery staple"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustSync(true)
}

// Nothing is renamed into place until every temporary file has been written,
// so a preparation failure leaves the previous set intact.
func TestPreparationFailureLeavesSetUntouched(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	h.gw.Rotate("my-cert", map[string][]byte{"tls.crt": []byte(certV2), "tls.key": []byte(keyV2)})

	// Make the second file impossible to write by replacing its directory
	// entry with one that cannot be created in.
	blocked := filepath.Join(h.dir, "blocked")
	if err := os.MkdirAll(blocked, 0o500); err != nil {
		t.Fatal(err)
	}
	h.exposure.Targets[1].Path = filepath.Join(blocked, "tls.key")

	if _, err := h.sync(); err == nil {
		t.Skip("writing into a read-only directory succeeded; test needs an unprivileged user")
	}
	// tls.crt is the first file and was written to a temporary file, but must
	// not have been renamed over the installed one.
	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q, want the previous version: a partial set was installed", got)
	}
	// And no temporary files were left behind.
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestPartialInstallationIsRecoveredWithoutCommittingState(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)

	etagPath := filepath.Join(h.stateDir, "my-cert.etag")
	stampPath := filepath.Join(h.stateDir, "my-cert.stamp")
	oldETag, err := os.ReadFile(etagPath)
	if err != nil {
		t.Fatal(err)
	}
	oldStamp, err := os.ReadFile(stampPath)
	if err != nil {
		t.Fatal(err)
	}

	h.gw.Rotate("my-cert", map[string][]byte{"tls.crt": []byte(certV2), "tls.key": []byte(keyV2)})
	keyPath := h.exposure.Targets[1].Path
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	// Staging still succeeds beside this directory, but the second rename
	// cannot replace a directory. The first rename has already landed.
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := h.sync(); err == nil {
		t.Fatal("partial installation succeeded")
	}
	if got := h.read("tls.crt"); got != certV2 {
		t.Fatalf("first target = %q, want the partially installed new value", got)
	}
	if got, err := os.ReadFile(etagPath); err != nil || string(got) != string(oldETag) {
		t.Fatalf("ETag changed after partial installation: %q, %v", got, err)
	}
	if got, err := os.ReadFile(stampPath); err != nil || string(got) != string(oldStamp) {
		t.Fatalf("stamp changed after partial installation: %q, %v", got, err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	h.mustSync(true)
	if got := h.read("tls.crt"); got != certV2 {
		t.Fatalf("tls.crt after recovery = %q", got)
	}
	if got := h.read("tls.key"); got != keyV2 {
		t.Fatalf("tls.key after recovery = %q", got)
	}
	newETag, err := os.ReadFile(etagPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(newETag) == string(oldETag) {
		t.Fatal("recovery did not commit the new ETag")
	}
	newStamp, err := os.ReadFile(stampPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(newStamp) == string(oldStamp) {
		t.Fatal("recovery did not update the stamp")
	}
}

func TestLogsNeverContainSecretsOrCredentials(t *testing.T) {
	h := newHarness(t)
	h.mustSync(true)
	h.gw.SetStatus("my-cert", 503)
	_, _ = h.sync()
	h.gw.SetStatus("my-cert", 0)
	h.gw.Remove("my-cert", "tls.key")
	_, _ = h.sync()

	logs := h.logs.String()
	for _, forbidden := range []string{"correct horse", "PRIVATE KEY", "BEGIN CERTIFICATE", "Q0E="} {
		if strings.Contains(logs, forbidden) {
			t.Fatalf("logs contain %q:\n%s", forbidden, logs)
		}
	}
}

func TestOnceRunsEveryExposureEvenIfOneFails(t *testing.T) {
	h := newHarness(t, `  - name: broken
    auth:
      username: fetcher
      passwordFile: /definitely/missing
    targets:
      - key: no-such-key
        path: /dev/null/impossible`)
	if len(h.cfg.Exposures) != 2 {
		t.Fatalf("configured %d exposures", len(h.cfg.Exposures))
	}
	err := h.runner.Once(context.Background())
	if err == nil {
		t.Fatal("Once must report the broken exposure")
	}
	// The healthy exposure was still installed.
	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q: a broken exposure stopped a healthy one", got)
	}
}

func TestOnChangeCommandFailureIsReportedButFilesStay(t *testing.T) {
	h := newHarness(t)
	h.exposure.OnChangeCommand = []string{"false"}
	changed, err := h.sync()
	if err == nil {
		t.Fatal("a failing onChangeCommand must be an error")
	}
	if !changed {
		t.Fatal("the files were installed, so the sync changed something")
	}
	if got := h.read("tls.crt"); got != certV1 {
		t.Fatal("the files should be installed before the command runs")
	}

	// A transient reload failure must be retried even though the files are
	// already current. The ETag is not committed until the command succeeds.
	h.exposure.OnChangeCommand = []string{"sh", "-c", "echo ran >> " + h.marker}
	h.mustSync(true)
	if got := h.reloads(); got != 1 {
		t.Fatalf("successful retry ran %d times, want 1", got)
	}
}

func TestOnChangeCommandDoesNotReceiveThePassword(t *testing.T) {
	h := newHarness(t)
	root := filepath.Dir(h.dir)
	dump := filepath.Join(root, "env")
	h.exposure.OnChangeCommand = []string{"sh", "-c", "env > " + dump}
	if _, err := h.sync(); err != nil {
		t.Fatal(err)
	}

	env, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env), "correct horse battery staple") {
		t.Fatal("the onChangeCommand inherited the password")
	}
}

func TestServePollsUntilCancelled(t *testing.T) {
	h := newHarness(t)
	h.cfg.Exposures[0].Interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.runner.Serve(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if total, _ := h.gw.Requests(); total >= 3 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Serve did not poll repeatedly")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop when the context was cancelled")
	}

	if got := h.read("tls.crt"); got != certV1 {
		t.Fatalf("tls.crt = %q", got)
	}
	// Repeated polling installs once and reloads once.
	if got := h.reloads(); got != 1 {
		t.Fatalf("onChangeCommand ran %d times, want 1", got)
	}
}
