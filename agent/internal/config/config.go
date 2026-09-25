// Package config loads and validates the agent YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultPath                 = "/etc/kube-secret-gateway-agent/config.yaml"
	DefaultStateDir             = "/var/lib/kube-secret-gateway-agent"
	DefaultMetricsListenAddress = "0.0.0.0:9091"

	DefaultTimeout = 30 * time.Second
	MinTimeout     = time.Second
	MaxTimeout     = 10 * time.Minute

	DefaultInterval = 5 * time.Minute
	MinInterval     = 10 * time.Second
	MaxInterval     = 7 * 24 * time.Hour

	DefaultFileMode fs.FileMode = 0o600
)

// Error lists every problem found while validating a configuration.
type Error struct {
	Problems []string
}

func (e *Error) Error() string {
	return "invalid configuration: " + strings.Join(e.Problems, "; ")
}

// Config is a validated configuration.
type Config struct {
	Gateway   Gateway
	Metrics   Metrics
	Exposures []Exposure
}

// Gateway is where and how to reach kube-secret-gateway.
type Gateway struct {
	// URL is the base URL, with any trailing slash removed. Exposure requests
	// are made to URL + "/exposures/" + name.
	URL     *url.URL
	CAFile  string
	Timeout time.Duration
}

// Metrics configures the Prometheus listener used in continuous mode.
type Metrics struct {
	ListenAddress string
}

// Auth locates one exposure's HTTP Basic Auth credentials.
type Auth struct {
	Username     string
	PasswordFile string
}

// Resolve reads the password immediately before a request so rotation takes
// effect without restarting the agent.
func (a Auth) Resolve(exposureName string) (username, password string, err error) {
	data, err := os.ReadFile(a.PasswordFile)
	if err != nil {
		return "", "", fmt.Errorf("exposure %q: passwordFile: %w", exposureName, err)
	}
	password = string(data)
	if password == "" {
		return "", "", fmt.Errorf("exposure %q: passwordFile %s is empty", exposureName, a.PasswordFile)
	}
	return a.Username, password, nil
}

// Exposure is one server exposure and its local synchronization lifecycle.
type Exposure struct {
	Name            string
	Auth            Auth
	Interval        time.Duration
	OnChangeCommand []string
	Targets         []Target
}

// Target is one exposure key and its absolute local destination.
type Target struct {
	Key  string
	Path string
	Mode fs.FileMode
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading configuration: %w", err)
	}
	return Parse(data)
}

// Parse validates one YAML document. Unknown fields are errors.
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
	Gateway   gatewayDoc    `yaml:"gateway"`
	Metrics   metricsDoc    `yaml:"metrics"`
	Exposures []exposureDoc `yaml:"exposures"`
}

type gatewayDoc struct {
	URL     string `yaml:"url"`
	CAFile  string `yaml:"caFile"`
	Timeout string `yaml:"timeout"`
}

type metricsDoc struct {
	ListenAddress *string `yaml:"listenAddress"`
}

type exposureDoc struct {
	Name            string      `yaml:"name"`
	Auth            *authDoc    `yaml:"auth"`
	Interval        string      `yaml:"interval"`
	Targets         []targetDoc `yaml:"targets"`
	OnChangeCommand []string    `yaml:"onChangeCommand"`
}

type authDoc struct {
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"passwordFile"`
}

type targetDoc struct {
	Key  string `yaml:"key"`
	Path string `yaml:"path"`
	Mode string `yaml:"mode"`
}

const dns1123LabelPattern = `[a-z0-9]([-a-z0-9]*[a-z0-9])?`

var (
	nameRE = regexp.MustCompile(`^` + dns1123LabelPattern + `(\.` + dns1123LabelPattern + `)*$`)
	keyRE  = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

func (d *document) resolve() (*Config, error) {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	cfg := &Config{Metrics: Metrics{ListenAddress: DefaultMetricsListenAddress}}

	switch {
	case d.Gateway.URL == "":
		add("gateway.url is required")
	default:
		u, err := url.Parse(d.Gateway.URL)
		switch {
		case err != nil:
			add("gateway.url %q: %v", d.Gateway.URL, err)
		case u.Scheme != "http" && u.Scheme != "https":
			add("gateway.url %q: scheme must be http or https", d.Gateway.URL)
		case u.Host == "":
			add("gateway.url %q: no host", d.Gateway.URL)
		case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
			add("gateway.url %q: must not carry credentials, a query or a fragment", d.Gateway.URL)
		default:
			u.Path = strings.TrimSuffix(u.Path, "/")
			cfg.Gateway.URL = u
		}
	}
	cfg.Gateway.CAFile = d.Gateway.CAFile
	cfg.Gateway.Timeout = DefaultTimeout
	if d.Gateway.Timeout != "" {
		switch timeout, err := time.ParseDuration(d.Gateway.Timeout); {
		case err != nil:
			add("gateway.timeout %q: %v", d.Gateway.Timeout, err)
		case timeout < MinTimeout || timeout > MaxTimeout:
			add("gateway.timeout %s is outside %s..%s", timeout, MinTimeout, MaxTimeout)
		default:
			cfg.Gateway.Timeout = timeout
		}
	}

	if d.Metrics.ListenAddress != nil {
		cfg.Metrics.ListenAddress = *d.Metrics.ListenAddress
	}
	if err := validateListenAddress(cfg.Metrics.ListenAddress); err != nil {
		add("metrics.listenAddress: %v", err)
	}

	if len(d.Exposures) == 0 {
		add("exposures must list at least one exposure")
	}
	seenName := make(map[string]int, len(d.Exposures))
	seenPath := make(map[string]string)
	for i, raw := range d.Exposures {
		where := fmt.Sprintf("exposures[%d]", i)
		e := Exposure{Name: raw.Name, Interval: DefaultInterval}
		switch {
		case raw.Name == "":
			add("%s: name is required", where)
		case !nameRE.MatchString(raw.Name) || len(raw.Name) > 253:
			add("%s: name %q is not a valid exposure name", where, raw.Name)
		default:
			if j, dup := seenName[raw.Name]; dup {
				add("%s: duplicate exposure name %q (already used by exposures[%d])", where, raw.Name, j)
			} else {
				seenName[raw.Name] = i
			}
		}

		if raw.Auth == nil {
			add("%s.auth: required", where)
		} else {
			e.Auth = Auth{Username: raw.Auth.Username, PasswordFile: raw.Auth.PasswordFile}
			if raw.Auth.Username == "" {
				add("%s.auth.username: required", where)
			}
			switch {
			case raw.Auth.PasswordFile == "":
				add("%s.auth.passwordFile: required", where)
			case !filepath.IsAbs(raw.Auth.PasswordFile):
				add("%s.auth.passwordFile: %q must be an absolute path", where, raw.Auth.PasswordFile)
			}
		}

		if raw.Interval != "" {
			switch interval, err := time.ParseDuration(raw.Interval); {
			case err != nil:
				add("%s.interval %q: %v", where, raw.Interval, err)
			case interval < MinInterval || interval > MaxInterval:
				add("%s.interval %s is outside %s..%s", where, interval, MinInterval, MaxInterval)
			default:
				e.Interval = interval
			}
		}
		if raw.OnChangeCommand != nil {
			if len(raw.OnChangeCommand) == 0 || raw.OnChangeCommand[0] == "" {
				add("%s.onChangeCommand must start with a command to run", where)
			} else {
				e.OnChangeCommand = append([]string(nil), raw.OnChangeCommand...)
			}
		}

		if len(raw.Targets) == 0 {
			add("%s.targets: at least one target is required", where)
		}
		seenKey := make(map[string]int, len(raw.Targets))
		for j, target := range raw.Targets {
			targetWhere := fmt.Sprintf("%s.targets[%d]", where, j)
			t := Target{Key: target.Key, Mode: DefaultFileMode}
			switch {
			case target.Key == "":
				add("%s.key: required", targetWhere)
			case !keyRE.MatchString(target.Key):
				add("%s.key: %q is not a valid Secret key", targetWhere, target.Key)
			default:
				if first, dup := seenKey[target.Key]; dup {
					add("%s.key: duplicate key %q (already used by %s.targets[%d])", targetWhere, target.Key, where, first)
				} else {
					seenKey[target.Key] = j
				}
			}
			switch {
			case target.Path == "":
				add("%s.path: required", targetWhere)
			case !filepath.IsAbs(target.Path):
				add("%s.path: %q must be absolute", targetWhere, target.Path)
			case strings.HasSuffix(target.Path, string(filepath.Separator)):
				add("%s.path: %q must name a file, not a directory", targetWhere, target.Path)
			default:
				cleanPath := filepath.Clean(target.Path)
				t.Path = cleanPath
				if owner, dup := seenPath[cleanPath]; dup {
					add("%s.path: %q normalizes to %q, already installed by %s", targetWhere, target.Path, cleanPath, owner)
				} else {
					seenPath[cleanPath] = targetWhere
				}
			}
			if target.Mode != "" {
				switch mode, err := strconv.ParseUint(target.Mode, 8, 32); {
				case err != nil || !strings.HasPrefix(target.Mode, "0"):
					add("%s.mode: %q must be octal and start with 0, such as \"0640\"", targetWhere, target.Mode)
				case mode&^0o777 != 0:
					add("%s.mode: %q must not set bits outside 0777", targetWhere, target.Mode)
				default:
					t.Mode = fs.FileMode(mode)
				}
			}
			e.Targets = append(e.Targets, t)
		}
		cfg.Exposures = append(cfg.Exposures, e)
	}

	if len(problems) > 0 {
		return nil, &Error{Problems: problems}
	}
	return cfg, nil
}

func validateListenAddress(addr string) error {
	if addr == "" {
		return errors.New("must not be empty")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: expected host:port such as \"0.0.0.0:9091\"", addr)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port %q in %q", port, addr)
	}
	return nil
}
