package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway-agent/internal/config"
)

const minimal = `
gateway:
  url: https://gateway.example.com
exposures:
  - name: my-cert
    username: fetcher
    passwordFile: /etc/kube-secret-gateway-agent/password
bundles:
  - name: nginx-tls
    exposure: my-cert
    files:
      tls.crt: /etc/ssl/nginx/tls.crt
      tls.key: /etc/ssl/nginx/tls.key
`

func mustParse(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestMinimalConfiguration(t *testing.T) {
	cfg := mustParse(t, minimal)

	if got := cfg.Gateway.URL.String(); got != "https://gateway.example.com" {
		t.Fatalf("gateway.url = %q", got)
	}
	if cfg.Gateway.Timeout != config.DefaultTimeout {
		t.Fatalf("timeout = %s, want the default %s", cfg.Gateway.Timeout, config.DefaultTimeout)
	}
	if len(cfg.Bundles) != 1 {
		t.Fatalf("%d bundles", len(cfg.Bundles))
	}
	b := cfg.Bundles[0]
	if b.Interval != config.DefaultInterval {
		t.Fatalf("interval = %s, want the default %s", b.Interval, config.DefaultInterval)
	}
	if b.OnChangeCommand != nil {
		t.Fatalf("onChangeCommand = %v, want none", b.OnChangeCommand)
	}
	// Files are sorted by key, so behaviour does not depend on YAML order.
	if len(b.Files) != 2 || b.Files[0].Key != "tls.crt" || b.Files[1].Key != "tls.key" {
		t.Fatalf("files = %+v", b.Files)
	}
	for _, f := range b.Files {
		if f.Mode != config.DefaultFileMode {
			t.Fatalf("%s mode = %o, want %o", f.Key, f.Mode, config.DefaultFileMode)
		}
	}
	if cr := cfg.Credentials(b); cr.Username != "fetcher" || cr.PasswordFile != "/etc/kube-secret-gateway-agent/password" {
		t.Fatalf("credentials = %+v", cr)
	}
}

func TestFullConfiguration(t *testing.T) {
	cfg := mustParse(t, `
gateway:
  url: https://gateway.example.com/ksg/
  caFile: /etc/ssl/certs/internal-ca.crt
  timeout: 10s
exposures:
  - name: my-cert
    username: fetcher
    passwordFile: /etc/kube-secret-gateway-agent/my-cert.password
  - name: api-token
    credentialsFile: /etc/kube-secret-gateway-agent/api-token.credentials
  - name: ca-bundle
    username: fetcher
    passwordEnv: KSG_CA_BUNDLE_PASSWORD
bundles:
  - name: nginx-tls
    exposure: my-cert
    interval: 1h
    onChangeCommand: [systemctl, reload, nginx]
    files:
      tls.key: /etc/ssl/nginx/tls.key
      tls.crt: {path: /etc/ssl/nginx/tls.crt, mode: "0644"}
  - name: api-token
    exposure: api-token
    interval: 10m
    files:
      token: {path: /etc/app/token, mode: "0640"}
`)
	// A base path is kept, and a trailing slash removed, so joining
	// "bundles/{exposure}" gives exactly one slash.
	if got := cfg.Gateway.URL.String(); got != "https://gateway.example.com/ksg" {
		t.Fatalf("gateway.url = %q", got)
	}
	if got := cfg.Gateway.URL.JoinPath("bundles", "my-cert").String(); got != "https://gateway.example.com/ksg/bundles/my-cert" {
		t.Fatalf("bundle URL = %q", got)
	}
	if cfg.Gateway.Timeout != 10*time.Second || cfg.Gateway.CAFile != "/etc/ssl/certs/internal-ca.crt" {
		t.Fatalf("gateway = %+v", cfg.Gateway)
	}

	nginx := cfg.Bundles[0]
	if nginx.Interval != time.Hour {
		t.Fatalf("interval = %s", nginx.Interval)
	}
	if got := nginx.Files[0]; got.Key != "tls.crt" || got.Path != "/etc/ssl/nginx/tls.crt" || got.Mode != 0o644 {
		t.Fatalf("files[0] = %+v", got)
	}
	if got := nginx.Files[1]; got.Key != "tls.key" || got.Mode != config.DefaultFileMode {
		t.Fatalf("files[1] = %+v", got)
	}
	if got := strings.Join(nginx.OnChangeCommand, " "); got != "systemctl reload nginx" {
		t.Fatalf("onChangeCommand = %q", got)
	}
	// Only the password-holding variable is named, once.
	if got := cfg.PasswordEnvNames(); len(got) != 1 || got[0] != "KSG_CA_BUNDLE_PASSWORD" {
		t.Fatalf("PasswordEnvNames = %v", got)
	}
}

func TestInvalidConfigurations(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want string
	}{
		{"empty", "", "configuration is empty"},
		{"unknown field", minimal + "\nnonsense: 1\n", "field nonsense not found"},
		{"two documents", minimal + "\n---\n" + minimal, "single YAML document"},
		{"no gateway url", strings.Replace(minimal, "  url: https://gateway.example.com", "  caFile: /x", 1), "gateway.url is required"},
		{"bad scheme", strings.Replace(minimal, "https://gateway.example.com", "ftp://gateway.example.com", 1), "scheme must be http or https"},
		{"no host", strings.Replace(minimal, "https://gateway.example.com", "https:///bundles", 1), "no host"},
		{"url with credentials", strings.Replace(minimal, "https://gateway.example.com", "https://u:p@gateway.example.com", 1), "must not carry credentials"},
		{"url with query", strings.Replace(minimal, "https://gateway.example.com", "https://gateway.example.com?a=1", 1), "must not carry credentials, a query or a fragment"},
		{"timeout too short", strings.Replace(minimal, "  url:", "  timeout: 1ms\n  url:", 1), "outside 1s..10m0s"},
		{"no exposures", "gateway:\n  url: https://g.example.com\nbundles:\n  - name: b\n    exposure: e\n    files: {k: /tmp/k}\n", "at least one exposure"},
		{"no bundles", "gateway:\n  url: https://g.example.com\nexposures:\n  - name: e\n    username: u\n    passwordEnv: P\n", "at least one bundle"},
		{"no credential source", strings.Replace(minimal, "    passwordFile: /etc/kube-secret-gateway-agent/password", "", 1), "one of credentialsFile, passwordFile or passwordEnv is required"},
		{"two credential sources", strings.Replace(minimal, "    passwordFile: /etc/kube-secret-gateway-agent/password", "    passwordFile: /etc/p\n    passwordEnv: P", 1), "mutually exclusive"},
		{"username with credentialsFile", strings.Replace(minimal, "    passwordFile: /etc/kube-secret-gateway-agent/password", "    credentialsFile: /etc/c", 1), "username belongs in the credentialsFile"},
		{"no username", strings.Replace(minimal, "    username: fetcher\n", "", 1), "username is required"},
		{"relative password file", strings.Replace(minimal, "/etc/kube-secret-gateway-agent/password", "password", 1), "must be an absolute path"},
		{"bad exposure name", strings.Replace(minimal, "name: my-cert", "name: My_Cert", 1), "is not a valid exposure name"},
		{"duplicate exposure", strings.Replace(minimal, "bundles:", "  - name: my-cert\n    username: u\n    passwordEnv: P\nbundles:", 1), "duplicate name"},
		{"unknown exposure", strings.Replace(minimal, "    exposure: my-cert", "    exposure: other", 1), `exposure "other" is not declared`},
		{"no exposure on bundle", strings.Replace(minimal, "    exposure: my-cert\n", "", 1), "exposure is required"},
		{"bad bundle name", strings.Replace(minimal, "name: nginx-tls", "name: ../escape", 1), "is not a valid bundle name"},
		{"interval too short", strings.Replace(minimal, "    exposure: my-cert", "    exposure: my-cert\n    interval: 1s", 1), "outside 10s..168h0m0s"},
		{"interval unparseable", strings.Replace(minimal, "    exposure: my-cert", "    exposure: my-cert\n    interval: soon", 1), "interval \"soon\""},
		{"no files", strings.Replace(minimal, "    files:\n      tls.crt: /etc/ssl/nginx/tls.crt\n      tls.key: /etc/ssl/nginx/tls.key\n", "", 1), "at least one Secret key"},
		{"relative path", strings.Replace(minimal, "/etc/ssl/nginx/tls.crt", "tls.crt", 1), "must be absolute"},
		{"directory path", strings.Replace(minimal, "/etc/ssl/nginx/tls.crt", "/etc/ssl/nginx/", 1), "must name a file"},
		{"bad key", strings.Replace(minimal, "tls.crt:", "tls/crt:", 1), "is not a valid Secret key"},
		{"empty command", strings.Replace(minimal, "    exposure: my-cert", "    exposure: my-cert\n    onChangeCommand: []", 1), "must start with a command"},
		{"mode not octal", strings.Replace(minimal, "tls.crt: /etc/ssl/nginx/tls.crt", `tls.crt: {path: /etc/ssl/nginx/tls.crt, mode: "644"}`, 1), "must be octal and start with 0"},
		{"mode too wide", strings.Replace(minimal, "tls.crt: /etc/ssl/nginx/tls.crt", `tls.crt: {path: /etc/ssl/nginx/tls.crt, mode: "04755"}`, 1), "must not set bits outside 0777"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("accepted an invalid configuration, wanted %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Two bundles writing the same file would fight over it, so it is rejected at
// startup rather than producing files that change on every run.
func TestDuplicateInstallPathRejected(t *testing.T) {
	_, err := config.Parse([]byte(minimal + `
  - name: other
    exposure: my-cert
    files:
      ca.crt: /etc/ssl/nginx/tls.crt
`))
	if err == nil || !strings.Contains(err.Error(), "already installed by") {
		t.Fatalf("err = %v, want a duplicate path error", err)
	}
}

// Every problem is reported at once, so one run of the command is enough to
// fix a configuration.
func TestAllProblemsReportedTogether(t *testing.T) {
	_, err := config.Parse([]byte(`
gateway:
  url: nonsense
exposures:
  - name: BAD
bundles:
  - name: b
    exposure: missing
    files:
      k: relative/path
`))
	if err == nil {
		t.Fatal("expected errors")
	}
	var cfgErr *config.Error
	if !asError(err, &cfgErr) {
		t.Fatalf("err is %T, want *config.Error", err)
	}
	if len(cfgErr.Problems) < 4 {
		t.Fatalf("reported %d problems, want every one of them: %v", len(cfgErr.Problems), cfgErr.Problems)
	}
}

func asError(err error, target **config.Error) bool {
	e, ok := err.(*config.Error)
	if ok {
		*target = e
	}
	return ok
}

func TestResolveCredentials(t *testing.T) {
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "password")
	credentialsFile := filepath.Join(dir, "credentials")
	if err := os.WriteFile(passwordFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialsFile, []byte("someone:else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KSG_TEST_PW", "from-env")

	cfg := mustParse(t, `
gateway:
  url: https://g.example.com
exposures:
  - name: from-file
    username: fetcher
    passwordFile: `+passwordFile+`
  - name: from-credentials
    credentialsFile: `+credentialsFile+`
  - name: from-env
    username: fetcher
    passwordEnv: KSG_TEST_PW
  - name: missing-file
    username: fetcher
    passwordFile: `+filepath.Join(dir, "absent")+`
  - name: missing-env
    username: fetcher
    passwordEnv: KSG_TEST_ABSENT
bundles:
  - name: a
    exposure: from-file
    files: {k: /tmp/ksg-a}
  - name: b
    exposure: from-credentials
    files: {k: /tmp/ksg-b}
  - name: c
    exposure: from-env
    files: {k: /tmp/ksg-c}
  - name: d
    exposure: missing-file
    files: {k: /tmp/ksg-d}
  - name: e
    exposure: missing-env
    files: {k: /tmp/ksg-e}
`)
	for _, tc := range []struct{ bundle, user, pass, wantErr string }{
		{"a", "fetcher", "s3cret", ""},
		{"b", "someone", "else", ""},
		{"c", "fetcher", "from-env", ""},
		{"d", "", "", "passwordFile"},
		{"e", "", "", "KSG_TEST_ABSENT is not set"},
	} {
		t.Run(tc.bundle, func(t *testing.T) {
			var bundle config.Bundle
			for _, b := range cfg.Bundles {
				if b.Name == tc.bundle {
					bundle = b
				}
			}
			user, pass, err := cfg.Credentials(bundle).Resolve()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// A trailing newline in the file is not part of the password.
			if user != tc.user || pass != tc.pass {
				t.Fatalf("resolved %q/%q, want %q/%q", user, pass, tc.user, tc.pass)
			}
		})
	}
}

// The example configuration is shipped as documentation, so it must stay
// loadable as the schema changes.
func TestShippedExampleIsValid(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "examples", "config.yaml"))
	if err != nil {
		t.Fatalf("examples/config.yaml: %v", err)
	}
	if len(cfg.Bundles) != 1 {
		t.Fatalf("the example should focus on one certificate bundle, got %d", len(cfg.Bundles))
	}
	b := cfg.Bundles[0]
	if b.Name != "nginx-tls" || b.Exposure != "my-cert" {
		t.Fatalf("unexpected example bundle: %+v", b)
	}
	if got := strings.Join(b.OnChangeCommand, " "); got != "systemctl reload nginx" {
		t.Fatalf("example onChangeCommand = %q", got)
	}
	cr := cfg.Credentials(b)
	if cr.PasswordFile == "" {
		t.Fatal("the example should use a password file")
	}
	if len(b.Files) != 2 || b.Files[0].Key != "tls.crt" || b.Files[0].Mode != 0o644 || b.Files[1].Key != "tls.key" {
		t.Fatalf("example should install tls.crt and tls.key with an explicit certificate mode: %+v", b.Files)
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "reading configuration") {
		t.Fatalf("err = %v", err)
	}
}
