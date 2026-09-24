package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway-agent/internal/gwtest"
)

// setup starts a fake gateway and writes an agent configuration for it. It returns
// the configuration path, the directory files are installed into, and the
// gateway.
func setup(t *testing.T, bundles string) (configPath, installDir string, gw *gwtest.Gateway) {
	t.Helper()
	gw = gwtest.New()
	t.Cleanup(gw.Close)
	gw.Set("my-cert", gwtest.Exposure{
		Username: "fetcher",
		Password: "hunter2",
		Values:   map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY")},
	})

	root := t.TempDir()
	installDir = filepath.Join(root, "ssl")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(root, "password")
	if err := os.WriteFile(passwordFile, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if bundles == "" {
		bundles = fmt.Sprintf(`
  - name: nginx-tls
    exposure: my-cert
    files:
      tls.crt: %s/tls.crt
      tls.key: %s/tls.key
`, installDir, installDir)
	} else {
		bundles = strings.ReplaceAll(bundles, "$DIR", installDir)
	}

	configPath = filepath.Join(root, "config.yaml")
	body := fmt.Sprintf(`
gateway:
  url: %s
exposures:
  - name: my-cert
    username: fetcher
    passwordFile: %s
bundles:%s`, gw.URL(), passwordFile, bundles)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, installDir, gw
}

// exec runs the command as the process would and returns its exit code and
// whatever it wrote to stderr.
func exec(t *testing.T, ctx context.Context, args ...string) (int, string) {
	t.Helper()
	var stderr strings.Builder
	code := run(ctx, args, &stderr)
	return code, stderr.String()
}

func TestOnceInstallsAndExitsZero(t *testing.T) {
	configPath, dir, gw := setup(t, "")
	stateDir := filepath.Join(t.TempDir(), "state")

	code, stderr := exec(t, context.Background(), "-config", configPath, "-state-dir", stateDir, "-once")
	if code != 0 {
		t.Fatalf("exit code %d, want 0\n%s", code, stderr)
	}
	for name, want := range map[string]string{"tls.crt": "CERT", "tls.key": "KEY"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	// Credentials and values never appear on stderr.
	if strings.Contains(stderr, "hunter2") || strings.Contains(stderr, "CERT") {
		t.Fatalf("stderr leaked: %s", stderr)
	}

	// A second run downloads nothing.
	code, stderr = exec(t, context.Background(), "-config", configPath, "-state-dir", stateDir, "-once")
	if code != 0 {
		t.Fatalf("second run: exit code %d\n%s", code, stderr)
	}
	total, notModified := gw.Requests()
	if total != 2 || notModified != 1 {
		t.Fatalf("gateway saw %d requests, %d of them 304; want 2 and 1", total, notModified)
	}
}

func TestOnceReturnsOneWhenABundleFails(t *testing.T) {
	configPath, dir, gw := setup(t, "")
	gw.SetStatus("my-cert", 503)
	code, stderr := exec(t, context.Background(), "-config", configPath, "-state-dir", filepath.Join(t.TempDir(), "state"), "-once")
	if code != 1 {
		t.Fatalf("exit code %d, want 1\n%s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.crt")); !os.IsNotExist(err) {
		t.Fatal("a failed fetch installed a file")
	}
}

func TestBundleSelection(t *testing.T) {
	bundles := `
  - name: nginx-tls
    exposure: my-cert
    files:
      tls.crt: $DIR/tls.crt
  - name: other
    exposure: my-cert
    files:
      tls.key: $DIR/tls.key
`
	configPath, dir, _ := setup(t, bundles)
	stateDir := filepath.Join(t.TempDir(), "state")

	code, stderr := exec(t, context.Background(), "-config", configPath, "-state-dir", stateDir, "-once", "-bundle", "other")
	if code != 0 {
		t.Fatalf("exit code %d\n%s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatalf("the selected bundle was not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.crt")); !os.IsNotExist(err) {
		t.Fatal("an unselected bundle was installed")
	}

	code, stderr = exec(t, context.Background(), "-config", configPath, "-state-dir", stateDir, "-once", "-bundle", "nope")
	if code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	// The message says what is configured, so a typo is easy to fix.
	for _, want := range []string{"no such bundle: nope", "nginx-tls", "other"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr %q does not mention %q", stderr, want)
		}
	}
}

// -check validates everything that can be validated locally, without asking
// the gateway for anything.
func TestCheckDoesNotContactTheGateway(t *testing.T) {
	configPath, dir, gw := setup(t, "")
	code, stderr := exec(t, context.Background(), "-config", configPath, "-check")
	if code != 0 {
		t.Fatalf("exit code %d, want 0\n%s", code, stderr)
	}
	if total, _ := gw.Requests(); total != 0 {
		t.Fatalf("-check made %d requests", total)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.crt")); !os.IsNotExist(err) {
		t.Fatal("-check installed a file")
	}
	if !strings.Contains(stderr, "valid") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestCheckCatchesAnUnreadablePasswordFile(t *testing.T) {
	configPath, _, _ := setup(t, "")
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	// Point the exposure at a password file that does not exist. Without the
	// startup check this would only surface at the first fetch, which may be
	// hours away.
	broken := strings.Replace(string(body), "/password\n", "/password-gone\n", 1)
	if err := os.WriteFile(configPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stderr := exec(t, context.Background(), "-config", configPath, "-check")
	if code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	if !strings.Contains(stderr, "passwordFile") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	configPath, _, _ := setup(t, "")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unexpected argument", []string{"-config", configPath, "extra"}, "unexpected arguments"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"bad log level", []string{"-config", configPath, "-log-level", "loud"}, "unknown log level"},
		{"bad log format", []string{"-config", configPath, "-log-format", "xml"}, "unknown log format"},
		{"missing config", []string{"-config", filepath.Join(t.TempDir(), "absent.yaml")}, "reading configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := exec(t, context.Background(), tc.args...)
			if code != 2 {
				t.Fatalf("exit code %d, want 2\n%s", code, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr %q does not mention %q", stderr, tc.want)
			}
		})
	}
}

func TestVersionFlag(t *testing.T) {
	code, stderr := exec(t, context.Background(), "-version")
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if !strings.Contains(stderr, appName) {
		t.Fatalf("stderr = %q", stderr)
	}
}

// Without -once the command runs until it is told to stop. Cancelling the
// parent context is what SIGTERM does to the real process.
func TestDaemonStopsOnCancellation(t *testing.T) {
	configPath, dir, _ := setup(t, "")
	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		var stderr strings.Builder
		code := run(ctx, []string{"-config", configPath, "-state-dir", filepath.Join(t.TempDir(), "state")}, &stderr)
		done <- result{code, stderr.String()}
	}()

	// Wait for the first sync to land before stopping.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "tls.crt")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the daemon never installed the bundle")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case got := <-done:
		if got.code != 0 {
			t.Fatalf("exit code %d, want 0\n%s", got.code, got.stderr)
		}
		if !strings.Contains(got.stderr, "stopped") {
			t.Fatalf("no clean shutdown in the log: %s", got.stderr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not stop")
	}
}
