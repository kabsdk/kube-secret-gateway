package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kube-secret-gateway/internal/exposure"
)

const specExample = `
server:
  listenAddress: ":8080"

  trustedProxies:
    - 10.42.0.0/16

kubernetes:
  defaultNamespace: certificates
  reconcileInterval: 5m

secrets:
  - secretRef:
      name: my-cert

    allowedCidrs:
      - 10.10.30.40/32
      - 10.10.30.41/32

    auth:
      type: basicAuth
      secretRef:
        namespace: certificate-auth
        name: my-cert-fetcher-credentials

    excludeKeys:
      - tls.key

  - name: matrix-prod

    secretRef:
      namespace: matrix-prod
      name: matrix-cert

    allowedCidrs:
      - 10.10.40.20/32

    auth:
      type: basicAuth
      secretRef:
        namespace: certificate-auth
        name: matrix-fetcher-credentials

    includeKeys:
      - tls.crt
      - tls.key
`

func TestParseSpecExample(t *testing.T) {
	cfg, err := Parse([]byte(specExample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Server.ListenAddress != ":8080" {
		t.Errorf("ListenAddress = %q", cfg.Server.ListenAddress)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}; !equalPrefixes(cfg.Server.TrustedProxies, want) {
		t.Errorf("TrustedProxies = %v, want %v", cfg.Server.TrustedProxies, want)
	}
	if cfg.ReconcileInterval != 5*time.Minute {
		t.Errorf("ReconcileInterval = %v", cfg.ReconcileInterval)
	}
	if len(cfg.Exposures) != 2 {
		t.Fatalf("got %d exposures, want 2", len(cfg.Exposures))
	}

	first := cfg.Exposures[0]
	if first.Name != "my-cert" {
		t.Errorf("first exposure name = %q, want name defaulted from secretRef.name", first.Name)
	}
	if want := (exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}); first.Source != want {
		t.Errorf("first source = %v, want %v", first.Source, want)
	}
	if want := (exposure.Auth{Type: exposure.AuthBasic, SecretRef: exposure.SecretRef{Namespace: "certificate-auth", Name: "my-cert-fetcher-credentials"}}); first.Auth != want {
		t.Errorf("first auth = %v, want %v", first.Auth, want)
	}
	if !equalPrefixes(first.AllowedCIDRs, []netip.Prefix{netip.MustParsePrefix("10.10.30.40/32"), netip.MustParsePrefix("10.10.30.41/32")}) {
		t.Errorf("first allowed CIDRs = %v", first.AllowedCIDRs)
	}
	if first.Keys.Exposes("tls.key") || !first.Keys.Exposes("tls.crt") || !first.Keys.Exposes("anything") {
		t.Error("first exposure: excludeKeys not applied")
	}

	second := cfg.Exposures[1]
	if second.Name != "matrix-prod" {
		t.Errorf("second exposure name = %q", second.Name)
	}
	if want := (exposure.SecretRef{Namespace: "matrix-prod", Name: "matrix-cert"}); second.Source != want {
		t.Errorf("second source = %v, want %v", second.Source, want)
	}
	if got := second.Keys.RequiredKeys(); strings.Join(got, ",") != "tls.crt,tls.key" {
		t.Errorf("second required keys = %v", got)
	}
	if second.Keys.Exposes("ca.crt") {
		t.Error("second exposure: key outside includeKeys is exposed")
	}
}

// minimal renders one exposure with overridable fragments.
func minimal(extra string) string {
	return `
kubernetes:
  defaultNamespace: certificates
secrets:
  - secretRef:
      name: my-cert
    allowedCidrs: [10.0.0.1/32]
    auth:
      type: basicAuth
      secretRef:
        name: creds
` + extra
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal("")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Server.ListenAddress != DefaultListenAddress {
		t.Errorf("ListenAddress = %q, want default %q", cfg.Server.ListenAddress, DefaultListenAddress)
	}
	if cfg.ReconcileInterval != DefaultReconcileInterval {
		t.Errorf("ReconcileInterval = %v, want default %v", cfg.ReconcileInterval, DefaultReconcileInterval)
	}
	if len(cfg.Server.TrustedProxies) != 0 {
		t.Errorf("TrustedProxies = %v, want none", cfg.Server.TrustedProxies)
	}
	e := cfg.Exposures[0]
	if e.Keys.RequiredKeys() != nil || !e.Keys.Exposes("tls.crt") || !e.Keys.Exposes("tls.key") {
		t.Error("without includeKeys/excludeKeys every key must be exposed and none required")
	}
}

func TestNamespaces(t *testing.T) {
	t.Run("explicit namespace wins over default", func(t *testing.T) {
		cfg := mustParse(t, `
kubernetes:
  defaultNamespace: certificates
secrets:
  - secretRef: {namespace: prod, name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: auth, name: creds}}
`)
		e := cfg.Exposures[0]
		if e.Source != (exposure.SecretRef{Namespace: "prod", Name: "my-cert"}) {
			t.Errorf("source = %v", e.Source)
		}
		if e.Auth.SecretRef != (exposure.SecretRef{Namespace: "auth", Name: "creds"}) {
			t.Errorf("auth = %v", e.Auth.SecretRef)
		}
	})
	t.Run("default namespace applies to source and auth", func(t *testing.T) {
		cfg := mustParse(t, minimal(""))
		e := cfg.Exposures[0]
		if e.Source != (exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}) {
			t.Errorf("source = %v", e.Source)
		}
		if e.Auth.SecretRef != (exposure.SecretRef{Namespace: "certificates", Name: "creds"}) {
			t.Errorf("auth = %v", e.Auth.SecretRef)
		}
	})
	t.Run("explicit namespaces need no default", func(t *testing.T) {
		mustParse(t, `
secrets:
  - secretRef: {namespace: prod, name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: auth, name: creds}}
`)
	})
}

func TestNamePath(t *testing.T) {
	cfg := mustParse(t, `
secrets:
  - name: matrix-prod
    secretRef: {namespace: prod, name: matrix-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: auth, name: creds}}
`)
	if got := cfg.Exposures[0].Name; got != "matrix-prod" {
		t.Errorf("name = %q", got)
	}
}

func TestKeyFilters(t *testing.T) {
	t.Run("includeKeys only", func(t *testing.T) {
		cfg := mustParse(t, minimal("    includeKeys: [tls.crt, tls.key]\n"))
		k := cfg.Exposures[0].Keys
		if !k.Exposes("tls.crt") || !k.Exposes("tls.key") || k.Exposes("ca.crt") {
			t.Error("includeKeys filter wrong")
		}
		if !k.Required("tls.crt") || k.Required("ca.crt") {
			t.Error("included keys must be required")
		}
	})
	t.Run("excludeKeys only", func(t *testing.T) {
		cfg := mustParse(t, minimal("    excludeKeys: [tls.key]\n"))
		k := cfg.Exposures[0].Keys
		if k.Exposes("tls.key") || !k.Exposes("tls.crt") || k.Required("tls.crt") {
			t.Error("excludeKeys filter wrong")
		}
	})
}

func TestValidationFailures(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing exposures", "kubernetes: {defaultNamespace: certificates}\n", "at least one exposure"},
		{"empty secrets list", "secrets: []\n", "at least one exposure"},
		{"missing namespace without default", `
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: auth, name: creds}}
`, "secrets[0].secretRef.namespace: not set and kubernetes.defaultNamespace is empty"},
		{"unresolved auth namespace", `
secrets:
  - secretRef: {namespace: prod, name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].auth.secretRef.namespace: not set and kubernetes.defaultNamespace is empty"},
		{"duplicate exposure name", minimal(`
  - name: my-cert
    secretRef: {name: other}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`), `secrets[1]: duplicate exposure name "my-cert"`},
		{"defaulted exposure name collision", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {namespace: a, name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
  - secretRef: {namespace: b, name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, `secrets[1]: duplicate exposure name "my-cert"`},
		{"missing source secret name", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - name: x
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].secretRef.name: required"},
		{"invalid source secret name", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: My_Cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].secretRef.name: invalid Secret name"},
		{"invalid namespace", `
secrets:
  - secretRef: {namespace: Not.A.Namespace, name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {namespace: auth, name: creds}}
`, "secrets[0].secretRef.namespace: invalid namespace"},
		{"invalid default namespace", "kubernetes: {defaultNamespace: \"bad/ns\"}\n", "kubernetes.defaultNamespace: invalid namespace"},
		{"invalid exposure name", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - name: "../etc"
    secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].name: invalid exposure name"},
		{"missing allowedCidrs", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].allowedCidrs: at least one CIDR is required"},
		{"empty allowedCidrs", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: []
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].allowedCidrs: at least one CIDR is required"},
		{"invalid allowed CIDR", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.300/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, `secrets[0].allowedCidrs[0]: invalid CIDR "10.0.0.300/32"`},
		{"allowed CIDR without prefix length", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, `secrets[0].allowedCidrs[0]: invalid CIDR "10.0.0.1"`},
		{"allowed CIDR with host bits", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.10.30.40/24]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "host bits are set (the network is 10.10.30.0/24)"},
		{"duplicate allowed CIDR", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32, 10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`, "secrets[0].allowedCidrs[1]: duplicate"},
		{"invalid trusted proxy CIDR", "server: {trustedProxies: [10.42.0.0/33]}\n" + minimal(""), `server.trustedProxies[0]: invalid CIDR "10.42.0.0/33"`},
		{"garbage trusted proxy", "server: {trustedProxies: [traefik]}\n" + minimal(""), `server.trustedProxies[0]: invalid CIDR "traefik"`},
		{"missing auth", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
`, "secrets[0].auth: required"},
		{"missing auth type", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {secretRef: {name: creds}}
`, "secrets[0].auth.type: required"},
		{"unsupported auth type", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: bearerToken, secretRef: {name: creds}}
`, `secrets[0].auth.type: unsupported auth type "bearerToken"`},
		{"missing auth secret name", `
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth}
`, "secrets[0].auth.secretRef.name: required"},
		{"includeKeys and excludeKeys together", minimal("    includeKeys: [tls.crt]\n    excludeKeys: [tls.key]\n"), "includeKeys and excludeKeys are mutually exclusive"},
		{"empty includeKeys", minimal("    includeKeys: []\n"), "secrets[0].includeKeys: must not be empty when set"},
		{"empty excludeKeys", minimal("    excludeKeys: []\n"), "secrets[0].excludeKeys: must not be empty when set"},
		{"duplicate includeKeys", minimal("    includeKeys: [tls.crt, tls.crt]\n"), "secrets[0].includeKeys[1]: duplicate"},
		{"duplicate excludeKeys", minimal("    excludeKeys: [tls.key, tls.key]\n"), "secrets[0].excludeKeys[1]: duplicate"},
		{"invalid key with slash", minimal("    includeKeys: [tls/crt]\n"), `secrets[0].includeKeys[0]: invalid Secret key "tls/crt"`},
		{"invalid dot-dot key", minimal("    excludeKeys: [\"..\"]\n"), `secrets[0].excludeKeys[0]: invalid Secret key ".."`},
		{"empty listen address", "server: {listenAddress: \"\"}\n" + minimal(""), "server.listenAddress: must not be empty"},
		{"listen address without port", "server: {listenAddress: \"0.0.0.0\"}\n" + minimal(""), "server.listenAddress: invalid address"},
		{"listen address with bad port", "server: {listenAddress: \":http-alt\"}\n" + minimal(""), "server.listenAddress: invalid port"},
		{"zero reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: 0s}\n" + minimalSecrets, "kubernetes.reconcileInterval: 0s is out of range"},
		{"bare zero reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: 0}\n" + minimalSecrets, "kubernetes.reconcileInterval: 0s is out of range"},
		{"negative reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: -5m}\n" + minimalSecrets, "kubernetes.reconcileInterval: -5m0s is out of range"},
		{"too short reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: 1s}\n" + minimalSecrets, "kubernetes.reconcileInterval: 1s is out of range"},
		{"too long reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: 48h}\n" + minimalSecrets, "kubernetes.reconcileInterval: 48h0m0s is out of range"},
		{"unitless reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: 300}\n" + minimalSecrets, "kubernetes.reconcileInterval: invalid duration \"300\""},
		{"garbage reconcile interval", "kubernetes: {defaultNamespace: certificates, reconcileInterval: often}\n" + minimalSecrets, "kubernetes.reconcileInterval: invalid duration"},
		{"empty configuration", "", "configuration is empty"},
		{"multiple documents", minimal("") + "---\nsecrets: []\n", "single YAML document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

const minimalSecrets = `
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: [10.0.0.1/32]
    auth: {type: basicAuth, secretRef: {name: creds}}
`

func TestMalformedYAML(t *testing.T) {
	cases := map[string]string{
		"syntax error":  "secrets: [\n  - {name: x",
		"wrong type":    "secrets: {name: x}\n",
		"unknown field": minimal("    excludekeys: [tls.key]\n"),
		"unknown top":   "servers: {}\n" + minimal(""),
		"duplicate key": "kubernetes: {defaultNamespace: a}\nkubernetes: {defaultNamespace: b}\n" + minimalSecrets,
		"tab indented":  "secrets:\n\t- name: x\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), "malformed YAML") {
				t.Fatalf("got %v, want malformed YAML error", err)
			}
		})
	}
}

func TestAllProblemsReported(t *testing.T) {
	_, err := Parse([]byte(`
server: {trustedProxies: [nope]}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: []
    auth: {type: magic}
`))
	var cfgErr *Error
	if !errors.As(err, &cfgErr) {
		t.Fatalf("got %v, want *Error", err)
	}
	if len(cfgErr.Problems) < 5 {
		t.Fatalf("want every problem reported, got %d: %v", len(cfgErr.Problems), cfgErr.Problems)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(specExample), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("Load of a missing file succeeded")
	}
}

func TestIPv6(t *testing.T) {
	cfg := mustParse(t, `
server: {trustedProxies: ["fd00:42::/64"]}
kubernetes: {defaultNamespace: certificates}
secrets:
  - secretRef: {name: my-cert}
    allowedCidrs: ["2001:db8::10/128", "10.0.0.0/8"]
    auth: {type: basicAuth, secretRef: {name: creds}}
`)
	e := cfg.Exposures[0]
	if !e.AllowsClient(netip.MustParseAddr("2001:db8::10")) || e.AllowsClient(netip.MustParseAddr("2001:db8::11")) {
		t.Error("IPv6 allowed CIDR not applied")
	}
	if !e.AllowsClient(netip.MustParseAddr("::ffff:10.1.2.3")) {
		t.Error("IPv4-mapped address must match IPv4 network")
	}
}

func TestIPv4MappedCIDRRejected(t *testing.T) {
	_, err := Parse([]byte(minimal("") + "\n" + `
  - name: other
    secretRef: {name: other}
    allowedCidrs: ["::ffff:10.0.0.0/104"]
    auth: {type: basicAuth, secretRef: {name: creds}}
`))
	if err == nil || !strings.Contains(err.Error(), "IPv4 notation") {
		t.Fatalf("got %v, want IPv4 notation error", err)
	}
}

func mustParse(t *testing.T, doc string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func equalPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMetricsSection(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := mustParse(t, minimal(""))
		if cfg.Metrics.ListenAddress != DefaultMetricsListenAddress || cfg.Metrics.Auth != nil || cfg.Metrics.TLS != nil {
			t.Fatalf("metrics = %+v, want default address, no auth, no TLS", cfg.Metrics)
		}
		if cfg.Server.TLS != nil {
			t.Fatal("server TLS must be off by default")
		}
	})
	t.Run("auth with default namespace", func(t *testing.T) {
		cfg := mustParse(t, "metrics:\n  listenAddress: \":9464\"\n  auth: {type: basicAuth, secretRef: {name: scrape-creds}}\n"+minimal(""))
		if cfg.Metrics.ListenAddress != ":9464" {
			t.Errorf("listen address = %q", cfg.Metrics.ListenAddress)
		}
		want := exposure.Auth{Type: exposure.AuthBasic, SecretRef: exposure.SecretRef{Namespace: "certificates", Name: "scrape-creds"}}
		if cfg.Metrics.Auth == nil || *cfg.Metrics.Auth != want {
			t.Errorf("auth = %+v, want %+v", cfg.Metrics.Auth, want)
		}
	})
	t.Run("tls on both listeners", func(t *testing.T) {
		cfg := mustParse(t, `
server:
  tls: {certFile: /tls/tls.crt, keyFile: /tls/tls.key}
metrics:
  tls: {certFile: /mtls/tls.crt, keyFile: /mtls/tls.key}
`+minimal(""))
		if *cfg.Server.TLS != (TLS{CertFile: "/tls/tls.crt", KeyFile: "/tls/tls.key"}) {
			t.Errorf("server TLS = %+v", cfg.Server.TLS)
		}
		if *cfg.Metrics.TLS != (TLS{CertFile: "/mtls/tls.crt", KeyFile: "/mtls/tls.key"}) {
			t.Errorf("metrics TLS = %+v", cfg.Metrics.TLS)
		}
	})
	t.Run("distinct hosts on the same port", func(t *testing.T) {
		mustParse(t, "server: {listenAddress: \"10.0.0.1:8080\"}\nmetrics: {listenAddress: \"127.0.0.1:8080\"}\n"+minimal(""))
	})
}

func TestMetricsAndTLSValidationFailures(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"same port as server", "metrics: {listenAddress: \":8080\"}\n" + minimal(""), "metrics.listenAddress: \":8080\" uses the same port as server.listenAddress"},
		{"same port, wildcard host", "server: {listenAddress: \"0.0.0.0:9000\"}\nmetrics: {listenAddress: \"127.0.0.1:9000\"}\n" + minimal(""), "uses the same port"},
		{"empty metrics address", "metrics: {listenAddress: \"\"}\n" + minimal(""), "metrics.listenAddress: must not be empty"},
		{"invalid metrics address", "metrics: {listenAddress: \"9100\"}\n" + minimal(""), "metrics.listenAddress: invalid address"},
		{"unsupported metrics auth", "metrics: {auth: {type: bearerToken, secretRef: {name: x}}}\n" + minimal(""), `metrics.auth.type: unsupported auth type "bearerToken"`},
		{"metrics auth without secret name", "metrics: {auth: {type: basicAuth}}\n" + minimal(""), "metrics.auth.secretRef.name: required"},
		{"metrics auth namespace unresolved", "metrics: {auth: {type: basicAuth, secretRef: {name: x}}}\n" + minimalSecrets, "metrics.auth.secretRef.namespace: not set and kubernetes.defaultNamespace is empty"},
		{"server tls without key", "server: {tls: {certFile: /tls/tls.crt}}\n" + minimal(""), "server.tls.keyFile: required"},
		{"server tls without cert", "server: {tls: {keyFile: /tls/tls.key}}\n" + minimal(""), "server.tls.certFile: required"},
		{"empty metrics tls", "metrics: {tls: {}}\n" + minimal(""), "metrics.tls.certFile: required"},
		{"server tls caFile is not an option", "server: {tls: {certFile: a, keyFile: b, caFile: c}}\n" + minimal(""), "malformed YAML"},
		{"unknown metrics field", "metrics: {path: /metrics}\n" + minimal(""), "malformed YAML"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}
