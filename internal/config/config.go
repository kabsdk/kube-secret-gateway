// Package config loads and validates the YAML configuration and converts it
// into the source-independent exposure model.
//
// Validation is complete before anything else starts: a configuration that
// loads successfully has resolved namespaces, parsed CIDRs, unique exposure
// names and a sane reconcile interval. Whether the referenced Secrets exist is
// runtime state and is deliberately not checked here.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"kube-secret-gateway/internal/exposure"
)

const (
	// DefaultPath is where the configuration is read from unless overridden.
	DefaultPath = "/etc/kube-secret-gateway/config.yaml"
	// DefaultListenAddress is used when server.listenAddress is absent.
	DefaultListenAddress = ":8080"
	// DefaultMetricsListenAddress is used when metrics.listenAddress is absent.
	DefaultMetricsListenAddress = ":8081"
	// DefaultReconcileInterval is used when kubernetes.reconcileInterval is absent.
	DefaultReconcileInterval = 5 * time.Minute

	// MinReconcileInterval and MaxReconcileInterval bound the reconcile
	// interval. Reconciliation is a slow safety net next to the watches, not
	// the primary update mechanism, so very short intervals only add API load.
	MinReconcileInterval = 10 * time.Second
	MaxReconcileInterval = 24 * time.Hour
)

// Config is a validated configuration.
type Config struct {
	Server            Server
	Metrics           Metrics
	ReconcileInterval time.Duration
	Exposures         []exposure.Exposure
}

// Server configures the listener that serves Secret values, and nothing else.
type Server struct {
	ListenAddress string
	// TLS is nil when the listener serves plain HTTP.
	TLS            *TLS
	TrustedProxies []netip.Prefix
}

// Metrics configures the listener for /metrics, /healthz and /readyz.
type Metrics struct {
	ListenAddress string
	// TLS is nil when the listener serves plain HTTP.
	TLS *TLS
	// Auth protects /metrics when set. Its Secret must exist and be valid
	// when the gateway starts. The health probes are never authenticated:
	// the kubelet cannot present credentials without putting them into the
	// pod spec, and the probes reveal nothing.
	Auth *exposure.Auth
}

// TLS names PEM files with a serving certificate (followed by any
// intermediates, as in a cert-manager tls.crt) and its private key. The files
// are re-read when they change, so renewals need no restart.
type TLS struct {
	CertFile string
	KeyFile  string
}

// Error lists every problem found while validating a configuration.
type Error struct {
	Problems []string
}

func (e *Error) Error() string {
	return "invalid configuration: " + strings.Join(e.Problems, "; ")
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	return Parse(data)
}

// Parse validates a YAML configuration document. Unknown fields are rejected,
// so a misspelt option such as "excludekeys" cannot silently widen exposure.
func Parse(data []byte) (*Config, error) {
	var doc document
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &Error{Problems: []string{"configuration is empty"}}
		}
		return nil, fmt.Errorf("invalid configuration: malformed YAML: %w", err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return nil, fmt.Errorf("invalid configuration: malformed YAML: %w", err)
	default:
		return nil, &Error{Problems: []string{"configuration must be a single YAML document"}}
	}
	return doc.resolve()
}

type document struct {
	Server     serverSection     `yaml:"server"`
	Metrics    metricsSection    `yaml:"metrics"`
	Kubernetes kubernetesSection `yaml:"kubernetes"`
	Secrets    []secretSection   `yaml:"secrets"`
}

// Listen addresses are pointers so that an absent value (use the default)
// can be told apart from an explicitly empty one (rejected).

type serverSection struct {
	ListenAddress  *string     `yaml:"listenAddress"`
	TLS            *tlsSection `yaml:"tls"`
	TrustedProxies []string    `yaml:"trustedProxies"`
}

type metricsSection struct {
	ListenAddress *string      `yaml:"listenAddress"`
	TLS           *tlsSection  `yaml:"tls"`
	Auth          *authSection `yaml:"auth"`
}

type tlsSection struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

type kubernetesSection struct {
	DefaultNamespace  string  `yaml:"defaultNamespace"`
	ReconcileInterval *string `yaml:"reconcileInterval"`
}

type secretSection struct {
	Name         string       `yaml:"name"`
	SecretRef    secretRef    `yaml:"secretRef"`
	AllowedCIDRs []string     `yaml:"allowedCidrs"`
	Auth         *authSection `yaml:"auth"`
	IncludeKeys  []string     `yaml:"includeKeys"`
	ExcludeKeys  []string     `yaml:"excludeKeys"`
}

type secretRef struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

type authSection struct {
	Type      string    `yaml:"type"`
	SecretRef secretRef `yaml:"secretRef"`
}

// validator accumulates problems so that one run reports all of them.
type validator struct {
	problems []string
}

func (v *validator) addf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (d *document) resolve() (*Config, error) {
	v := &validator{}
	cfg := &Config{ReconcileInterval: DefaultReconcileInterval}

	defaultNS := d.Kubernetes.DefaultNamespace
	if defaultNS != "" {
		if err := exposure.ValidateNamespace(defaultNS); err != nil {
			v.addf("kubernetes.defaultNamespace: invalid namespace %q: %v", defaultNS, err)
		}
	}

	cfg.Server = Server{
		ListenAddress:  v.listenAddress("server.listenAddress", d.Server.ListenAddress, DefaultListenAddress),
		TLS:            v.tls("server.tls", d.Server.TLS),
		TrustedProxies: v.prefixes("server.trustedProxies", d.Server.TrustedProxies, false),
	}
	cfg.Metrics = Metrics{
		ListenAddress: v.listenAddress("metrics.listenAddress", d.Metrics.ListenAddress, DefaultMetricsListenAddress),
		TLS:           v.tls("metrics.tls", d.Metrics.TLS),
	}
	if listenersConflict(cfg.Server.ListenAddress, cfg.Metrics.ListenAddress) {
		v.addf("metrics.listenAddress: %q uses the same port as server.listenAddress %q; the metrics endpoints need their own port",
			cfg.Metrics.ListenAddress, cfg.Server.ListenAddress)
	}
	if d.Metrics.Auth != nil {
		a := v.auth("metrics.auth", d.Metrics.Auth, defaultNS)
		cfg.Metrics.Auth = &a
	}
	if s := d.Kubernetes.ReconcileInterval; s != nil {
		interval, err := parseReconcileInterval(*s)
		if err != nil {
			v.addf("kubernetes.reconcileInterval: %v", err)
		}
		cfg.ReconcileInterval = interval
	}

	if len(d.Secrets) == 0 {
		v.addf("secrets: at least one exposure must be configured")
	}
	firstUse := make(map[string]int, len(d.Secrets))
	for i := range d.Secrets {
		path := fmt.Sprintf("secrets[%d]", i)
		exp := d.Secrets[i].resolve(v, path, defaultNS)
		if exp.Name != "" {
			if j, dup := firstUse[exp.Name]; dup {
				v.addf("%s: duplicate exposure name %q (already used by secrets[%d]; names default to secretRef.name)", path, exp.Name, j)
			} else {
				firstUse[exp.Name] = i
			}
		}
		cfg.Exposures = append(cfg.Exposures, exp)
	}

	if len(v.problems) > 0 {
		return nil, &Error{Problems: v.problems}
	}
	return cfg, nil
}

func (s *secretSection) resolve(v *validator, path, defaultNS string) exposure.Exposure {
	exp := exposure.Exposure{
		Name:         s.Name,
		Source:       v.secretRef(path+".secretRef", s.SecretRef, defaultNS),
		AllowedCIDRs: v.prefixes(path+".allowedCidrs", s.AllowedCIDRs, true),
		Auth:         v.auth(path+".auth", s.Auth, defaultNS),
		Keys:         v.keyFilter(path, s.IncludeKeys, s.ExcludeKeys),
	}
	if exp.Name == "" {
		// A valid Secret name is always a valid exposure name, and an invalid
		// one has already been reported against secretRef.name.
		exp.Name = s.SecretRef.Name
	} else if err := exposure.ValidateName(exp.Name); err != nil {
		v.addf("%s.name: invalid exposure name %q: %v", path, exp.Name, err)
	}
	return exp
}

func (v *validator) secretRef(path string, ref secretRef, defaultNS string) exposure.SecretRef {
	out := exposure.SecretRef{Namespace: ref.Namespace, Name: ref.Name}
	if out.Name == "" {
		v.addf("%s.name: required", path)
	} else if err := exposure.ValidateSecretName(out.Name); err != nil {
		v.addf("%s.name: invalid Secret name %q: %v", path, out.Name, err)
	}
	if out.Namespace == "" {
		if defaultNS == "" {
			v.addf("%s.namespace: not set and kubernetes.defaultNamespace is empty", path)
		}
		out.Namespace = defaultNS
	} else if err := exposure.ValidateNamespace(out.Namespace); err != nil {
		v.addf("%s.namespace: invalid namespace %q: %v", path, out.Namespace, err)
	}
	return out
}

func (v *validator) prefixes(path string, values []string, required bool) []netip.Prefix {
	if required && len(values) == 0 {
		v.addf("%s: at least one CIDR is required (an empty list does not mean allow-all)", path)
		return nil
	}
	seen := make(map[netip.Prefix]int, len(values))
	out := make([]netip.Prefix, 0, len(values))
	for i, s := range values {
		p, err := exposure.ParsePrefix(s)
		if err != nil {
			v.addf("%s[%d]: %v", path, i, err)
			continue
		}
		if j, dup := seen[p]; dup {
			v.addf("%s[%d]: duplicate of %s[%d] (%s)", path, i, path, j, p)
			continue
		}
		seen[p] = i
		out = append(out, p)
	}
	return out
}

func (v *validator) auth(path string, a *authSection, defaultNS string) exposure.Auth {
	if a == nil {
		v.addf("%s: required", path)
		return exposure.Auth{}
	}
	switch exposure.AuthType(a.Type) {
	case exposure.AuthBasic:
	case "":
		v.addf("%s.type: required (supported: %s)", path, exposure.AuthBasic)
	default:
		v.addf("%s.type: unsupported auth type %q (supported: %s)", path, a.Type, exposure.AuthBasic)
	}
	return exposure.Auth{
		Type:      exposure.AuthType(a.Type),
		SecretRef: v.secretRef(path+".secretRef", a.SecretRef, defaultNS),
	}
}

// keyFilter distinguishes an absent list (nil) from an explicitly empty one:
// "includeKeys: []" would expose nothing and is rejected rather than being
// silently treated as "all keys".
func (v *validator) keyFilter(path string, include, exclude []string) exposure.KeyFilter {
	switch {
	case include != nil && exclude != nil:
		v.addf("%s: includeKeys and excludeKeys are mutually exclusive", path)
	case include != nil:
		if v.keys(path+".includeKeys", include) {
			return exposure.IncludeKeys(include...)
		}
	case exclude != nil:
		if v.keys(path+".excludeKeys", exclude) {
			return exposure.ExcludeKeys(exclude...)
		}
	}
	return exposure.KeyFilter{}
}

func (v *validator) keys(path string, keys []string) bool {
	if len(keys) == 0 {
		v.addf("%s: must not be empty when set", path)
		return false
	}
	ok := true
	seen := make(map[string]int, len(keys))
	for i, k := range keys {
		if err := exposure.ValidateKey(k); err != nil {
			v.addf("%s[%d]: invalid Secret key %q: %v", path, i, k, err)
			ok = false
			continue
		}
		if j, dup := seen[k]; dup {
			v.addf("%s[%d]: duplicate of %s[%d] (%q)", path, i, path, j, k)
			ok = false
			continue
		}
		seen[k] = i
	}
	return ok
}

func (v *validator) listenAddress(path string, value *string, def string) string {
	if value == nil {
		return def
	}
	if err := validateListenAddress(*value); err != nil {
		v.addf("%s: %v", path, err)
	}
	return *value
}

func (v *validator) tls(path string, t *tlsSection) *TLS {
	if t == nil {
		return nil
	}
	if t.CertFile == "" {
		v.addf("%s.certFile: required", path)
	}
	if t.KeyFile == "" {
		v.addf("%s.keyFile: required", path)
	}
	return &TLS{CertFile: t.CertFile, KeyFile: t.KeyFile}
}

// listenersConflict reports whether two listen addresses would compete for
// the same port: same port, and the same host or a wildcard on either side.
func listenersConflict(a, b string) bool {
	hostA, portA, errA := net.SplitHostPort(a)
	hostB, portB, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || portA != portB {
		return false
	}
	return hostA == hostB || isWildcardHost(hostA) || isWildcardHost(hostB)
}

func isWildcardHost(host string) bool {
	if host == "" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsUnspecified()
}

func validateListenAddress(addr string) error {
	if addr == "" {
		return errors.New("must not be empty")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: expected host:port such as \":8080\"", addr)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("invalid port %q in %q", port, addr)
	}
	return nil
}

func parseReconcileInterval(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: use a value with a unit such as \"5m\" or \"90s\"", s)
	}
	if d < MinReconcileInterval || d > MaxReconcileInterval {
		return 0, fmt.Errorf("%s is out of range: must be between %s and %s", d, MinReconcileInterval, MaxReconcileInterval)
	}
	return d, nil
}
