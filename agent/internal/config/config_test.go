package config_test

import (
	"errors"
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
    auth:
      username: fetcher
      passwordFile: /etc/kube-secret-gateway-agent/password
    targets:
      - key: tls.crt
        path: /etc/ssl/nginx/tls.crt
      - key: tls.key
        path: /etc/ssl/nginx/tls.key
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
		t.Fatalf("timeout = %s, want %s", cfg.Gateway.Timeout, config.DefaultTimeout)
	}
	if cfg.Metrics.ListenAddress != config.DefaultMetricsListenAddress {
		t.Fatalf("metrics.listenAddress = %q, want %q", cfg.Metrics.ListenAddress, config.DefaultMetricsListenAddress)
	}
	if len(cfg.Exposures) != 1 {
		t.Fatalf("exposures = %d, want 1", len(cfg.Exposures))
	}
	e := cfg.Exposures[0]
	if e.Name != "my-cert" || e.Interval != config.DefaultInterval {
		t.Fatalf("exposure = %+v", e)
	}
	if e.Auth.Username != "fetcher" || e.Auth.PasswordFile != "/etc/kube-secret-gateway-agent/password" {
		t.Fatalf("auth = %+v", e.Auth)
	}
	if e.OnChangeCommand != nil {
		t.Fatalf("onChangeCommand = %v, want none", e.OnChangeCommand)
	}
	if len(e.Targets) != 2 || e.Targets[0].Key != "tls.crt" || e.Targets[1].Key != "tls.key" {
		t.Fatalf("targets = %+v", e.Targets)
	}
	for _, target := range e.Targets {
		if target.Mode != config.DefaultFileMode {
			t.Fatalf("%s mode = %o, want %o", target.Key, target.Mode, config.DefaultFileMode)
		}
	}
}

func TestDottedExposureName(t *testing.T) {
	cfg := mustParse(t, strings.Replace(minimal, "name: my-cert", "name: certs.example.com", 1))
	if got := cfg.Exposures[0].Name; got != "certs.example.com" {
		t.Fatalf("exposure name = %q, want certs.example.com", got)
	}
}

func TestFullConfiguration(t *testing.T) {
	cfg := mustParse(t, `
gateway:
  url: https://gateway.example.com/ksg/
  caFile: /etc/ssl/certs/internal-ca.crt
  timeout: 10s
metrics:
  listenAddress: 192.0.2.20:9101
exposures:
  - name: my-cert
    auth:
      username: fetcher
      passwordFile: /etc/kube-secret-gateway-agent/my-cert.password
    interval: 1h
    onChangeCommand: [systemctl, reload, nginx]
    targets:
      - key: tls.crt
        path: /etc/ssl/nginx/tls.crt
        mode: "0644"
      - key: tls.key
        path: /etc/ssl/nginx/tls.key
  - name: api-token
    auth:
      username: app
      passwordFile: /etc/kube-secret-gateway-agent/api-token.password
    interval: 10m
    targets:
      - key: token
        path: /etc/app/token
        mode: "0640"
`)
	if got := cfg.Gateway.URL.String(); got != "https://gateway.example.com/ksg" {
		t.Fatalf("gateway.url = %q", got)
	}
	if got := cfg.Gateway.URL.JoinPath("exposures", "my-cert").String(); got != "https://gateway.example.com/ksg/exposures/my-cert" {
		t.Fatalf("exposure URL = %q", got)
	}
	if cfg.Gateway.Timeout != 10*time.Second || cfg.Gateway.CAFile != "/etc/ssl/certs/internal-ca.crt" {
		t.Fatalf("gateway = %+v", cfg.Gateway)
	}
	if cfg.Metrics.ListenAddress != "192.0.2.20:9101" {
		t.Fatalf("metrics = %+v", cfg.Metrics)
	}
	e := cfg.Exposures[0]
	if e.Interval != time.Hour || strings.Join(e.OnChangeCommand, " ") != "systemctl reload nginx" {
		t.Fatalf("exposure = %+v", e)
	}
	if got := e.Targets[0]; got.Key != "tls.crt" || got.Path != "/etc/ssl/nginx/tls.crt" || got.Mode != 0o644 {
		t.Fatalf("targets[0] = %+v", got)
	}
	if got := e.Targets[1]; got.Key != "tls.key" || got.Mode != config.DefaultFileMode {
		t.Fatalf("targets[1] = %+v", got)
	}
}

func TestInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"empty", "", "configuration is empty"},
		{"unknown field", minimal + "\nnonsense: 1\n", "field nonsense not found"},
		{"two documents", minimal + "\n---\n" + minimal, "single YAML document"},
		{"no gateway url", strings.Replace(minimal, "  url: https://gateway.example.com", "  caFile: /x", 1), "gateway.url is required"},
		{"bad scheme", strings.Replace(minimal, "https://gateway.example.com", "ftp://gateway.example.com", 1), "scheme must be http or https"},
		{"no host", strings.Replace(minimal, "https://gateway.example.com", "https:///exposures", 1), "no host"},
		{"url with credentials", strings.Replace(minimal, "https://gateway.example.com", "https://u:p@gateway.example.com", 1), "must not carry credentials"},
		{"url with query", strings.Replace(minimal, "https://gateway.example.com", "https://gateway.example.com?a=1", 1), "must not carry credentials"},
		{"timeout too short", strings.Replace(minimal, "  url:", "  timeout: 1ms\n  url:", 1), "outside 1s..10m0s"},
		{"empty metrics address", strings.Replace(minimal, "exposures:", "metrics:\n  listenAddress: \"\"\nexposures:", 1), "must not be empty"},
		{"bad metrics address", strings.Replace(minimal, "exposures:", "metrics:\n  listenAddress: localhost\nexposures:", 1), "expected host:port"},
		{"bad metrics port", strings.Replace(minimal, "exposures:", "metrics:\n  listenAddress: localhost:nope\nexposures:", 1), "invalid port"},
		{"no exposures", "gateway:\n  url: https://g.example.com\n", "at least one exposure"},
		{"missing auth", strings.Replace(minimal, "    auth:\n      username: fetcher\n      passwordFile: /etc/kube-secret-gateway-agent/password\n", "", 1), "auth: required"},
		{"no username", strings.Replace(minimal, "      username: fetcher\n", "", 1), "auth.username: required"},
		{"no password file", strings.Replace(minimal, "      passwordFile: /etc/kube-secret-gateway-agent/password\n", "", 1), "auth.passwordFile: required"},
		{"relative password file", strings.Replace(minimal, "/etc/kube-secret-gateway-agent/password", "password", 1), "must be an absolute path"},
		{"bad exposure name", strings.Replace(minimal, "name: my-cert", "name: My_Cert", 1), "not a valid exposure name"},
		{"empty exposure label", strings.Replace(minimal, "name: my-cert", "name: a..b", 1), "not a valid exposure name"},
		{"hyphen before exposure label", strings.Replace(minimal, "name: my-cert", "name: a-.b", 1), "not a valid exposure name"},
		{"duplicate exposure", minimal + strings.TrimPrefix(minimal[strings.Index(minimal, "  - name:"):], ""), "duplicate exposure name"},
		{"interval too short", strings.Replace(minimal, "    targets:", "    interval: 1s\n    targets:", 1), "outside 10s..168h0m0s"},
		{"interval unparseable", strings.Replace(minimal, "    targets:", "    interval: soon\n    targets:", 1), "interval \"soon\""},
		{"no targets", strings.Replace(minimal, "    targets:\n      - key: tls.crt\n        path: /etc/ssl/nginx/tls.crt\n      - key: tls.key\n        path: /etc/ssl/nginx/tls.key\n", "", 1), "at least one target"},
		{"empty key", strings.Replace(minimal, "key: tls.crt", "key: \"\"", 1), "key: required"},
		{"bad key", strings.Replace(minimal, "key: tls.crt", "key: tls/crt", 1), "not a valid Secret key"},
		{"duplicate key", strings.Replace(minimal, "key: tls.key", "key: tls.crt", 1), "duplicate key"},
		{"relative path", strings.Replace(minimal, "/etc/ssl/nginx/tls.crt", "tls.crt", 1), "must be absolute"},
		{"directory path", strings.Replace(minimal, "/etc/ssl/nginx/tls.crt", "/etc/ssl/nginx/", 1), "must name a file"},
		{"duplicate path", strings.Replace(minimal, "/etc/ssl/nginx/tls.key", "/etc/ssl/nginx/tls.crt", 1), "already installed by"},
		{"duplicate cleaned path", strings.Replace(minimal, "/etc/ssl/nginx/tls.key", "/etc/ssl/nginx/./tls.crt", 1), "already installed by"},
		{"empty command", strings.Replace(minimal, "    targets:", "    onChangeCommand: []\n    targets:", 1), "must start with a command"},
		{"mode not octal", strings.Replace(minimal, "        path: /etc/ssl/nginx/tls.crt", "        path: /etc/ssl/nginx/tls.crt\n        mode: \"644\"", 1), "must be octal"},
		{"mode too wide", strings.Replace(minimal, "        path: /etc/ssl/nginx/tls.crt", "        path: /etc/ssl/nginx/tls.crt\n        mode: \"04755\"", 1), "outside 0777"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestRemovedFieldsAreRejected(t *testing.T) {
	tests := map[string]string{
		"bundles":         minimal + "\nbundles: []\n",
		"credentialsFile": strings.Replace(minimal, "      passwordFile:", "      credentialsFile:", 1),
		"passwordEnv":     strings.Replace(minimal, "      passwordFile: /etc/kube-secret-gateway-agent/password", "      passwordEnv: PASSWORD", 1),
		"direct username": strings.Replace(minimal, "    auth:\n      username: fetcher\n      passwordFile: /etc/kube-secret-gateway-agent/password", "    username: fetcher\n    passwordFile: /etc/password", 1),
		"files":           strings.Replace(minimal, "    targets:", "    files:", 1),
		"exposure":        strings.Replace(minimal, "    targets:", "    exposure: other\n    targets:", 1),
	}
	for name, yaml := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "field") {
				t.Fatalf("removed field was accepted: %v", err)
			}
		})
	}
}

func TestAllProblemsReportedTogether(t *testing.T) {
	_, err := config.Parse([]byte(`
gateway:
  url: nonsense
exposures:
  - name: BAD
    auth: {}
    targets:
      - key: bad/key
        path: relative/path
`))
	if err == nil {
		t.Fatal("expected errors")
	}
	var cfgErr *config.Error
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err is %T, want *config.Error", err)
	}
	if len(cfgErr.Problems) < 5 {
		t.Fatalf("reported %d problems, want all of them: %v", len(cfgErr.Problems), cfgErr.Problems)
	}
}

func TestResolvePasswordFileAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("first\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := config.Auth{Username: "fetcher", PasswordFile: path}
	user, password, err := auth.Resolve("my-cert")
	if err != nil || user != "fetcher" || password != "first\r\n" {
		t.Fatalf("Resolve = %q/%q, %v", user, password, err)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, password, err = auth.Resolve("my-cert")
	if err != nil || password != "second\n" {
		t.Fatalf("rotated Resolve = %q, %v", password, err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Resolve("my-cert"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty password error = %v", err)
	}
}

func TestShippedExampleIsValid(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "examples", "config.yaml"))
	if err != nil {
		t.Fatalf("examples/config.yaml: %v", err)
	}
	if len(cfg.Exposures) != 1 {
		t.Fatalf("example exposures = %d, want 1", len(cfg.Exposures))
	}
	e := cfg.Exposures[0]
	if e.Name != "my-cert" || e.Auth.PasswordFile == "" {
		t.Fatalf("unexpected example exposure: %+v", e)
	}
	if strings.Join(e.OnChangeCommand, " ") != "systemctl reload nginx" {
		t.Fatalf("onChangeCommand = %q", e.OnChangeCommand)
	}
	if len(e.Targets) != 2 || e.Targets[0].Key != "tls.crt" || e.Targets[0].Mode != 0o644 || e.Targets[1].Key != "tls.key" {
		t.Fatalf("example targets = %+v", e.Targets)
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "reading configuration") {
		t.Fatalf("err = %v", err)
	}
}
