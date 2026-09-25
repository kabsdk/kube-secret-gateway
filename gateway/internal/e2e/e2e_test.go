package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kube-secret-gateway/internal/clientip"
	"kube-secret-gateway/internal/config"
	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/kubernetes/kubetest"
	"kube-secret-gateway/internal/metrics"
	"kube-secret-gateway/internal/resources"
	"kube-secret-gateway/internal/server"
)

// agentModule is the agent's module directory, relative to this package.
const agentModule = "../../../agent"

const gatewayConfig = `
kubernetes:
  defaultNamespace: certificates
exposures:
  - name: my-cert
    secretRef: {name: my-cert}
    keys: [tls.crt, tls.key, ca.crt]
    allowedCidrs: [127.0.0.1/32, "::1/128"]
    auth: {secretRef: {namespace: certificate-auth, name: fetcher}}

  - name: strict
    secretRef: {name: strict-cert}
    keys: [tls.crt, tls.key]
    allowedCidrs: [127.0.0.1/32, "::1/128"]
    auth: {secretRef: {namespace: certificate-auth, name: fetcher}}

  - name: elsewhere
    secretRef: {name: my-cert}
    keys: [tls.crt]
    allowedCidrs: [10.0.0.0/8]
    auth: {secretRef: {namespace: certificate-auth, name: fetcher}}
`

var (
	certRef   = exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}
	strictRef = exposure.SecretRef{Namespace: "certificates", Name: "strict-cert"}
	authRef   = exposure.SecretRef{Namespace: "certificate-auth", Name: "fetcher"}
)

var (
	buildOnce   sync.Once
	agentPath   string
	buildErr    error
	buildOutput []byte
)

// agentBinary builds the agent once per test run.
func agentBinary(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(agentModule, "go.mod")); err != nil {
		t.Skipf("agent module not found at %s: %v", agentModule, err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not available")
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "kube-secret-gateway-e2e-")
		if err != nil {
			buildErr = err
			return
		}
		agentPath = filepath.Join(dir, "kube-secret-gateway-agent")
		cmd := exec.Command("go", "build", "-o", agentPath, "./cmd/kube-secret-gateway-agent")
		cmd.Dir = agentModule
		buildOutput, buildErr = cmd.CombinedOutput()
	})
	if buildErr != nil {
		t.Fatalf("building the agent: %v\n%s", buildErr, buildOutput)
	}
	return agentPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if agentPath != "" {
		_ = os.RemoveAll(filepath.Dir(agentPath))
	}
	os.Exit(code)
}

type env struct {
	t          *testing.T
	api        *kubetest.FakeAPI
	mgr        *resources.Manager
	binary     string
	configPath string
	stateDir   string
	dir        string

	mu      sync.Mutex
	answers []int
}

// start runs the gateway on a loopback listener and writes an agent
// configuration for it. password is what the agent sends.
func start(t *testing.T, password string) *env {
	t.Helper()
	e := &env{t: t, api: kubetest.New(), binary: agentBinary(t), dir: t.TempDir()}
	e.stateDir = filepath.Join(e.dir, "state")
	e.api.Apply(certRef, map[string][]byte{"tls.crt": []byte("CERT-1"), "tls.key": []byte("KEY-1"), "ca.crt": []byte("CA")})
	e.api.Apply(authRef, map[string][]byte{"username": []byte("fetcher"), "password": []byte("s3cret")})

	cfg, err := config.Parse([]byte(gatewayConfig))
	if err != nil {
		t.Fatal(err)
	}
	e.mgr = resources.NewManager(e.api, exposure.ReferencedSecrets(cfg.Exposures), resources.Options{
		ReconcileInterval:   time.Hour,
		WatchTimeout:        time.Hour,
		InitialBackoff:      time.Millisecond,
		MaxBackoff:          5 * time.Millisecond,
		StableWatchDuration: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	e.mgr.Start(ctx)
	t.Cleanup(func() { cancel(); e.mgr.Wait() })
	if err := e.mgr.WaitInitialized(ctx); err != nil {
		t.Fatal(err)
	}
	m, err := metrics.New(cfg.Exposures, e.mgr)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.New(server.Options{
		Exposures: cfg.Exposures,
		Secrets:   e.mgr,
		ClientIP:  clientip.NewResolver(cfg.Server.TrustedProxies),
		Observer:  m,
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		handler.ServeHTTP(rec, r)
		e.mu.Lock()
		e.answers = append(e.answers, rec.status)
		e.mu.Unlock()
	}))
	t.Cleanup(gw.Close)

	passwordFile := filepath.Join(e.dir, "password")
	if err := os.WriteFile(passwordFile, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	e.configPath = filepath.Join(e.dir, "config.yaml")
	agentConfig := fmt.Sprintf(`
gateway:
  url: %[1]s
exposures:
  - name: my-cert
    auth: {username: fetcher, passwordFile: %[2]s}
    targets:
      - {key: tls.crt, path: %[3]s/tls.crt, mode: "0644"}
      - {key: tls.key, path: %[3]s/tls.key}
  - name: strict
    auth: {username: fetcher, passwordFile: %[2]s}
    targets:
      - {key: tls.crt, path: %[3]s/strict.crt}
      - {key: tls.key, path: %[3]s/strict.key}
  - name: elsewhere
    auth: {username: fetcher, passwordFile: %[2]s}
    targets:
      - {key: tls.crt, path: %[3]s/elsewhere.crt}
`, gw.URL, passwordFile, e.dir)
	if err := os.WriteFile(e.configPath, []byte(agentConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// sync runs the agent once for one exposure and returns its exit code and
// log output.
func (e *env) sync(exposure string) (int, string) {
	e.t.Helper()
	var out bytes.Buffer
	cmd := exec.Command(e.binary, "-config", e.configPath, "-state-dir", e.stateDir, "-once", "-exposure", exposure)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), out.String()
	default:
		e.t.Fatalf("running the agent: %v", err)
		return -1, ""
	}
}

// mustSync runs the agent and expects success, returning the status the
// gateway answered it with.
func (e *env) mustSync(exposure string) int {
	e.t.Helper()
	if code, out := e.sync(exposure); code != 0 {
		e.t.Fatalf("agent exited %d:\n%s", code, out)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.answers[len(e.answers)-1]
}

func (e *env) apply(ref exposure.SecretRef, data map[string][]byte) {
	e.t.Helper()
	rv := e.api.Apply(ref, data)
	e.eventually(func() bool { return e.mgr.Secret(ref).ResourceVersion == rv })
}

func (e *env) eventually(cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatal("timed out waiting for the gateway to observe a change")
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *env) expectFiles(crt, key string) {
	e.t.Helper()
	for name, want := range map[string]string{"tls.crt": crt, "tls.key": key} {
		got, err := os.ReadFile(filepath.Join(e.dir, name))
		if err != nil {
			e.t.Fatal(err)
		}
		if string(got) != want {
			e.t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func (e *env) expectAbsent(name string) {
	e.t.Helper()
	if _, err := os.Stat(filepath.Join(e.dir, name)); !os.IsNotExist(err) {
		e.t.Fatalf("%s was installed: %v", name, err)
	}
}

// TestInstallPollRotate is the everyday life of a client: install, poll
// without downloading, pick up a renewal as one consistent set, and fetch
// once more after the Secret is recreated.
func TestInstallPollRotate(t *testing.T) {
	e := start(t, "s3cret")

	if got := e.mustSync("my-cert"); got != http.StatusOK {
		t.Fatalf("first sync answered %d, want 200", got)
	}
	e.expectFiles("CERT-1", "KEY-1")
	if info, err := os.Stat(filepath.Join(e.dir, "tls.crt")); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("tls.crt mode: %v %v", info, err)
	}

	if got := e.mustSync("my-cert"); got != http.StatusNotModified {
		t.Fatalf("unchanged poll answered %d, want 304", got)
	}

	// A key the client does not install still changes the exposure's tag: one
	// tag covers the whole set.
	e.apply(certRef, map[string][]byte{"tls.crt": []byte("CERT-1"), "tls.key": []byte("KEY-1"), "ca.crt": []byte("CA-2")})
	if got := e.mustSync("my-cert"); got != http.StatusOK {
		t.Fatalf("after ca.crt changed: answered %d, want 200", got)
	}

	e.apply(certRef, map[string][]byte{"tls.crt": []byte("CERT-2"), "tls.key": []byte("KEY-2"), "ca.crt": []byte("CA-2")})
	if got := e.mustSync("my-cert"); got != http.StatusOK {
		t.Fatalf("after renewal: answered %d, want 200", got)
	}
	e.expectFiles("CERT-2", "KEY-2")

	// Recreating the Secret changes its UID, and with it every tag, even
	// though the values are identical.
	e.api.Delete(certRef)
	e.eventually(func() bool { return !e.mgr.Secret(certRef).Present })
	e.apply(certRef, map[string][]byte{"tls.crt": []byte("CERT-2"), "tls.key": []byte("KEY-2"), "ca.crt": []byte("CA-2")})
	if got := e.mustSync("my-cert"); got != http.StatusOK {
		t.Fatalf("after recreation: answered %d, want 200", got)
	}
	e.expectFiles("CERT-2", "KEY-2")
}

// TestFailuresInstallNothing covers the statuses the agent has to tell apart.
// None of them may touch a file.
func TestFailuresInstallNothing(t *testing.T) {
	expectFailure := func(t *testing.T, e *env, exposure, status string) {
		t.Helper()
		code, out := e.sync(exposure)
		if code != 1 || !strings.Contains(out, status) {
			t.Fatalf("agent exited %d, want 1 with a %s:\n%s", code, status, out)
		}
	}

	t.Run("503 when a configured key is missing", func(t *testing.T) {
		e := start(t, "s3cret")
		e.apply(strictRef, map[string][]byte{"tls.crt": []byte("STRICT-CERT")})
		expectFailure(t, e, "strict", "503")
		e.expectAbsent("strict.crt")

		e.apply(strictRef, map[string][]byte{"tls.crt": []byte("STRICT-CERT"), "tls.key": []byte("STRICT-KEY")})
		if got := e.mustSync("strict"); got != http.StatusOK {
			t.Fatalf("once complete: answered %d, want 200", got)
		}
	})

	t.Run("401 for a wrong password", func(t *testing.T) {
		e := start(t, "wrong")
		expectFailure(t, e, "my-cert", "401")
		e.expectAbsent("tls.crt")
	})

	t.Run("404 outside allowedCidrs", func(t *testing.T) {
		e := start(t, "s3cret")
		expectFailure(t, e, "elsewhere", "404")
		e.expectAbsent("elsewhere.crt")
	})
}
