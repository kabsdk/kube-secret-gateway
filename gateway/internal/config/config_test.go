package config

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"kube-secret-gateway/internal/exposure"
)

const specExample = `
server:
  listenAddress: ":8080"
  trustedProxies: [10.42.0.0/16]
metrics:
  listenAddress: ":8081"
  auth:
    secretRef: {namespace: monitoring, name: metrics-reader}
kubernetes:
  defaultNamespace: certificates
  reconcileInterval: 5m
exposures:
  - name: nginx-tls
    secretRef: {name: website-tls}
    keys: [tls.crt, tls.key]
    allowedCidrs: [10.10.40.30/32]
    auth:
      secretRef: {namespace: readers, name: nginx-tls-reader}
  - name: nginx-ca
    secretRef: {namespace: shared, name: website-tls}
    keys: [ca.crt]
    allowedCidrs: [10.10.40.31/32]
    auth:
      secretRef: {namespace: readers, name: nginx-ca-reader}
`

func TestParseExposureConfiguration(t *testing.T) {
	cfg, err := Parse([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddress != ":8080" || cfg.Metrics.ListenAddress != ":8081" {
		t.Fatalf("listener addresses not parsed: %+v %+v", cfg.Server, cfg.Metrics)
	}
	if cfg.ReconcileInterval != 5*time.Minute {
		t.Fatalf("reconcile interval = %v", cfg.ReconcileInterval)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}; !slices.Equal(cfg.Server.TrustedProxies, want) {
		t.Fatalf("trusted proxies = %v", cfg.Server.TrustedProxies)
	}
	if len(cfg.Exposures) != 2 {
		t.Fatalf("exposures = %d", len(cfg.Exposures))
	}
	e := cfg.Exposures[0]
	if e.Name != "nginx-tls" || e.Source != (exposure.SecretRef{Namespace: "certificates", Name: "website-tls"}) {
		t.Fatalf("exposure = %+v", e)
	}
	if !slices.Equal(e.Keys, []string{"tls.crt", "tls.key"}) {
		t.Fatalf("keys = %v", e.Keys)
	}
	if e.Auth.SecretRef != (exposure.SecretRef{Namespace: "readers", Name: "nginx-tls-reader"}) {
		t.Fatalf("auth = %+v", e.Auth)
	}
	if cfg.Metrics.Auth == nil || cfg.Metrics.Auth.SecretRef != (exposure.SecretRef{Namespace: "monitoring", Name: "metrics-reader"}) {
		t.Fatalf("metrics auth = %+v", cfg.Metrics.Auth)
	}
}

func minimal(extra string) string {
	return `
kubernetes:
  defaultNamespace: certificates
exposures:
  - name: my-cert
    secretRef: {name: my-cert}
    keys: [tls.crt]
    allowedCidrs: [10.0.0.1/32]
    auth:
      secretRef: {name: creds}
` + extra
}

func TestDefaultsAndNamespaces(t *testing.T) {
	cfg := mustParse(t, minimal(""))
	if cfg.Server.ListenAddress != DefaultListenAddress || cfg.Metrics.ListenAddress != DefaultMetricsListenAddress {
		t.Fatal("listener defaults not applied")
	}
	if cfg.ReconcileInterval != DefaultReconcileInterval {
		t.Fatalf("reconcile default = %v", cfg.ReconcileInterval)
	}
	e := cfg.Exposures[0]
	if e.Source.Namespace != "certificates" || e.Auth.SecretRef.Namespace != "certificates" {
		t.Fatalf("default namespace not applied: %+v", e)
	}

	cfg = mustParse(t, `
exposures:
  - name: explicit
    secretRef: {namespace: source, name: s}
    keys: [value]
    allowedCidrs: [10.0.0.1/32]
    auth: {secretRef: {namespace: auth, name: a}}
`)
	if cfg.Exposures[0].Source.Namespace != "source" || cfg.Exposures[0].Auth.SecretRef.Namespace != "auth" {
		t.Fatal("explicit namespace not retained")
	}
}

func TestValidationFailures(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{"no exposures", "kubernetes: {defaultNamespace: x}\n", "at least one exposure"},
		{"empty exposures", "exposures: []\n", "at least one exposure"},
		{"name required", strings.Replace(minimal(""), "  - name: my-cert\n", "  -\n", 1), ".name: required"},
		{"bad name", strings.Replace(minimal(""), "name: my-cert", "name: ../bad", 1), "invalid exposure name"},
		{"duplicate name", minimal(`  - name: my-cert
    secretRef: {name: other}
    keys: [value]
    allowedCidrs: [10.0.0.2/32]
    auth: {secretRef: {name: other-creds}}
`), "duplicate exposure name"},
		{"keys required", strings.Replace(minimal(""), "    keys: [tls.crt]\n", "", 1), "at least one key is required"},
		{"empty keys", strings.Replace(minimal(""), "keys: [tls.crt]", "keys: []", 1), "at least one key is required"},
		{"duplicate keys", strings.Replace(minimal(""), "[tls.crt]", "[tls.crt, tls.crt]", 1), "duplicate"},
		{"invalid key", strings.Replace(minimal(""), "[tls.crt]", "[tls/crt]", 1), "invalid Secret key"},
		{"source name required", strings.Replace(minimal(""), "secretRef: {name: my-cert}", "secretRef: {}", 1), "secretRef.name: required"},
		{"namespace required", strings.Replace(minimal(""), "kubernetes:\n  defaultNamespace: certificates\n", "", 1), "namespace: not set"},
		{"auth required", strings.Replace(minimal(""), "    auth:\n      secretRef: {name: creds}\n", "", 1), ".auth: required"},
		{"auth secret required", strings.Replace(minimal(""), "secretRef: {name: creds}", "secretRef: {}", 1), "auth.secretRef.name: required"},
		{"CIDR required", strings.Replace(minimal(""), "    allowedCidrs: [10.0.0.1/32]\n", "", 1), "at least one CIDR is required"},
		{"duplicate CIDR", strings.Replace(minimal(""), "[10.0.0.1/32]", "[10.0.0.1/32, 10.0.0.1/32]", 1), "duplicate"},
		{"host bits", strings.Replace(minimal(""), "10.0.0.1/32", "10.0.0.1/24", 1), "host bits are set"},
		{"short reconcile", "kubernetes: {defaultNamespace: certificates, reconcileInterval: 1s}\n" + strings.TrimPrefix(minimal(""), "\nkubernetes:\n  defaultNamespace: certificates\n"), "out of range"},
		{"same listener", "metrics: {listenAddress: \":8080\"}\n" + minimal(""), "uses the same port"},
		{"empty document", "", "configuration is empty"},
		{"multiple documents", minimal("") + "---\nexposures: []\n", "single YAML document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestRemovedFieldsAreRejected(t *testing.T) {
	cases := map[string]string{
		"secrets collection": strings.Replace(minimal(""), "exposures:", "secrets:", 1),
		"includeKeys":        strings.Replace(minimal(""), "keys:", "includeKeys:", 1),
		"excludeKeys":        minimal("    excludeKeys: [tls.key]\n"),
		"exposure auth type": strings.Replace(minimal(""), "    auth:\n", "    auth:\n      type: basicAuth\n", 1),
		"metrics auth type":  "metrics: {auth: {type: basicAuth, secretRef: {name: metrics}}}\n" + minimal(""),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "field") {
				t.Fatalf("removed field accepted: %v", err)
			}
		})
	}
}

func TestMalformedYAMLAndAllProblems(t *testing.T) {
	for _, doc := range []string{"exposures: [", "exposures: {name: x}", "unknown: true\n" + minimal("")} {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "malformed YAML") {
			t.Fatalf("%q: got %v", doc, err)
		}
	}
	_, err := Parse([]byte(`
server: {trustedProxies: [nope]}
exposures:
  - name: bad_name
    secretRef: {}
    keys: []
    allowedCidrs: []
`))
	var cfgErr *Error
	if !errors.As(err, &cfgErr) || len(cfgErr.Problems) < 5 {
		t.Fatalf("want accumulated problems, got %v", err)
	}
}

func TestShippedExamplesAreValid(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "examples", "config.yaml")); err != nil {
		t.Fatalf("config example: %v", err)
	}
	f, err := os.Open(filepath.Join("..", "..", "examples", "kubernetes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	for {
		var resource struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}
		err := dec.Decode(&resource)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if doc := resource.Data["config.yaml"]; resource.Kind == "ConfigMap" && doc != "" {
			if _, err := Parse([]byte(doc)); err != nil {
				t.Fatalf("Kubernetes ConfigMap: %v", err)
			}
			return
		}
	}
	t.Fatal("no config ConfigMap")
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(specExample), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func mustParse(t *testing.T, doc string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
