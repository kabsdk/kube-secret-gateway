// Package config loads and validates the YAML configuration.
//
// Validation is complete before anything else starts: a configuration that
// loads successfully has a usable gateway URL, a credential source for every
// exposure a bundle uses, absolute local paths that no two bundles share, and
// intervals inside sane bounds. Whether the gateway answers, and whether the
// credentials are correct, is runtime state and is deliberately not checked
// here.
//
// Credential values are not part of a loaded configuration. Only where to
// read them from is, so a long-running process does not hold passwords
// between fetches; see Credentials.Resolve.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	// DefaultPath is where the configuration is read from unless overridden.
	DefaultPath = "/etc/kube-secret-gateway-agent/config.yaml"
	// DefaultStateDir holds one state file and one stamp file per bundle.
	DefaultStateDir = "/var/lib/kube-secret-gateway-agent"

	// DefaultTimeout bounds one HTTP request to the gateway.
	DefaultTimeout = 30 * time.Second
	// MinTimeout and MaxTimeout bound gateway.timeout.
	MinTimeout = time.Second
	MaxTimeout = 10 * time.Minute

	// DefaultInterval is used when a bundle does not set one.
	DefaultInterval = 5 * time.Minute
	// MinInterval and MaxInterval bound a bundle's interval. The gateway
	// answers unchanged bundles with a bodyless 304, so polling is cheap, but
	// very short intervals only add requests.
	MinInterval = 10 * time.Second
	MaxInterval = 7 * 24 * time.Hour

	// DefaultFileMode is used for an installed file that sets no mode. Secret
	// values are private by default.
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
	Gateway  Gateway
	Bundles  []Bundle
	exposure map[string]Credentials
}

// Gateway is where and how to reach kube-secret-gateway.
type Gateway struct {
	// URL is the base URL, with any trailing slash removed. Bundle requests
	// are made to URL + "/bundles/" + exposure.
	URL *url.URL
	// CAFile, when set, is the only certificate authority trusted for the
	// gateway. Empty means the system pool.
	CAFile  string
	Timeout time.Duration
}

// Credentials says where an exposure's Basic Auth credentials are read from.
// The values themselves are never held in a Config.
type Credentials struct {
	Name     string
	Username string
	// Exactly one of the following is set.
	CredentialsFile string // one line, "username:password"
	PasswordFile    string // the password alone
	PasswordEnv     string // the name of an environment variable
}

// Bundle is one set of keys that is fetched, installed and reloaded together.
// It maps to exactly one exposure, and therefore to one Kubernetes Secret, so
// a fetch can never mix two versions of it.
type Bundle struct {
	Name     string
	Exposure string
	Interval time.Duration
	// OnChangeCommand is run, without a shell, after the files of this bundle
	// have been installed. Empty means nothing is run.
	OnChangeCommand []string
	// Files are the keys to install, sorted by key.
	Files []File
}

// File is one key of the bundle and where it is installed.
type File struct {
	Key  string
	Path string
	Mode fs.FileMode
}

// Credentials returns where to read the credentials of the exposure a bundle
// uses. Validation guarantees that every bundle's exposure is declared.
func (c *Config) Credentials(b Bundle) Credentials { return c.exposure[b.Exposure] }

// PasswordEnvNames returns every environment variable that holds a password,
// sorted. A command run after a change must not inherit them.
func (c *Config) PasswordEnvNames() []string {
	var names []string
	for _, cr := range c.exposure {
		if cr.PasswordEnv != "" && !slices.Contains(names, cr.PasswordEnv) {
			names = append(names, cr.PasswordEnv)
		}
	}
	slices.Sort(names)
	return names
}

// Resolve reads the username and password from their source. It is called
// before each fetch rather than at startup, so that a long-running process
// does not keep passwords in memory between fetches, and so that a rotated
// credentials file takes effect without a restart.
func (c Credentials) Resolve() (username, password string, err error) {
	switch {
	case c.CredentialsFile != "":
		data, err := os.ReadFile(c.CredentialsFile)
		if err != nil {
			return "", "", fmt.Errorf("exposure %q: credentialsFile: %w", c.Name, err)
		}
		line := strings.TrimRight(string(data), "\r\n")
		user, pass, ok := strings.Cut(line, ":")
		if !ok {
			return "", "", fmt.Errorf("exposure %q: credentialsFile %s: want one line of \"username:password\"", c.Name, c.CredentialsFile)
		}
		if user == "" || pass == "" {
			return "", "", fmt.Errorf("exposure %q: credentialsFile %s: username and password must both be set", c.Name, c.CredentialsFile)
		}
		return user, pass, nil
	case c.PasswordFile != "":
		data, err := os.ReadFile(c.PasswordFile)
		if err != nil {
			return "", "", fmt.Errorf("exposure %q: passwordFile: %w", c.Name, err)
		}
		// A trailing newline is stripped: editors add one, and the gateway
		// compares the password exactly.
		pass := strings.TrimRight(string(data), "\r\n")
		if pass == "" {
			return "", "", fmt.Errorf("exposure %q: passwordFile %s is empty", c.Name, c.PasswordFile)
		}
		return c.Username, pass, nil
	default:
		pass, ok := os.LookupEnv(c.PasswordEnv)
		if !ok {
			return "", "", fmt.Errorf("exposure %q: %s is not set in the environment", c.Name, c.PasswordEnv)
		}
		if pass == "" {
			return "", "", fmt.Errorf("exposure %q: %s is empty", c.Name, c.PasswordEnv)
		}
		return c.Username, pass, nil
	}
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading configuration: %w", err)
	}
	return Parse(data)
}

// Parse validates one YAML document. Unknown fields are errors, so a typo
// never silently disables something.
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

// The YAML shape. It exists only to be decoded; resolve turns it into a
// Config and is the only place that reports problems.
type document struct {
	Gateway   gatewayDoc    `yaml:"gateway"`
	Exposures []exposureDoc `yaml:"exposures"`
	Bundles   []bundleDoc   `yaml:"bundles"`
}

type gatewayDoc struct {
	URL     string `yaml:"url"`
	CAFile  string `yaml:"caFile"`
	Timeout string `yaml:"timeout"`
}

type exposureDoc struct {
	Name            string `yaml:"name"`
	Username        string `yaml:"username"`
	CredentialsFile string `yaml:"credentialsFile"`
	PasswordFile    string `yaml:"passwordFile"`
	PasswordEnv     string `yaml:"passwordEnv"`
}

type bundleDoc struct {
	Name            string             `yaml:"name"`
	Exposure        string             `yaml:"exposure"`
	Interval        string             `yaml:"interval"`
	OnChangeCommand []string           `yaml:"onChangeCommand"`
	Files           map[string]fileDoc `yaml:"files"`
}

// fileDoc accepts either a path on its own or a mapping with a mode, so the
// common case stays a single line.
type fileDoc struct {
	Path string `yaml:"path"`
	Mode string `yaml:"mode"`
}

func (f *fileDoc) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&f.Path)
	}
	type raw fileDoc // avoids recursing into this method
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*f = fileDoc(r)
	return nil
}

// Exposure and Secret key names are restricted by the gateway, which rejects
// anything else with a 404. Checking here turns a silent 404 into a startup
// error, and guarantees that no name needs percent-encoding in a URL.
var (
	nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	keyRE  = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
	// A bundle name is also a file name in the state directory.
	bundleNameRE = regexp.MustCompile(`^[a-zA-Z0-9]([-_a-zA-Z0-9.]*[a-zA-Z0-9])?$`)
)

func (d *document) resolve() (*Config, error) {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	cfg := &Config{exposure: make(map[string]Credentials, len(d.Exposures))}

	// gateway
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

	// exposures
	if len(d.Exposures) == 0 {
		add("exposures must list at least one exposure")
	}
	for i, e := range d.Exposures {
		where := fmt.Sprintf("exposures[%d]", i)
		switch {
		case e.Name == "":
			add("%s: name is required", where)
		case !nameRE.MatchString(e.Name) || len(e.Name) > 253:
			add("%s: name %q is not a valid exposure name", where, e.Name)
		default:
			where = fmt.Sprintf("exposure %q", e.Name)
			if _, dup := cfg.exposure[e.Name]; dup {
				add("%s: duplicate name", where)
				continue
			}
		}

		sources := 0
		for _, set := range []bool{e.CredentialsFile != "", e.PasswordFile != "", e.PasswordEnv != ""} {
			if set {
				sources++
			}
		}
		switch {
		case sources == 0:
			add("%s: one of credentialsFile, passwordFile or passwordEnv is required", where)
		case sources > 1:
			add("%s: credentialsFile, passwordFile and passwordEnv are mutually exclusive", where)
		}
		if e.CredentialsFile != "" && e.Username != "" {
			add("%s: username belongs in the credentialsFile, not in the configuration", where)
		}
		if e.CredentialsFile == "" && e.Username == "" && sources > 0 {
			add("%s: username is required unless credentialsFile is used", where)
		}
		for field, path := range map[string]string{"credentialsFile": e.CredentialsFile, "passwordFile": e.PasswordFile} {
			if path != "" && !strings.HasPrefix(path, "/") {
				add("%s: %s %q must be an absolute path", where, field, path)
			}
		}
		if e.Name != "" {
			cfg.exposure[e.Name] = Credentials{
				Name:            e.Name,
				Username:        e.Username,
				CredentialsFile: e.CredentialsFile,
				PasswordFile:    e.PasswordFile,
				PasswordEnv:     e.PasswordEnv,
			}
		}
	}

	// bundles
	if len(d.Bundles) == 0 {
		add("bundles must list at least one bundle")
	}
	seenBundle := make(map[string]struct{}, len(d.Bundles))
	seenPath := make(map[string]string, len(d.Bundles))
	for i, b := range d.Bundles {
		where := fmt.Sprintf("bundles[%d]", i)
		switch {
		case b.Name == "":
			add("%s: name is required", where)
		case !bundleNameRE.MatchString(b.Name) || len(b.Name) > 100:
			add("%s: name %q is not a valid bundle name", where, b.Name)
		default:
			where = fmt.Sprintf("bundle %q", b.Name)
			if _, dup := seenBundle[b.Name]; dup {
				add("%s: duplicate name", where)
				continue
			}
			seenBundle[b.Name] = struct{}{}
		}

		bundle := Bundle{Name: b.Name, Exposure: b.Exposure, Interval: DefaultInterval}
		switch {
		case b.Exposure == "":
			add("%s: exposure is required", where)
		case len(d.Exposures) > 0:
			if _, ok := cfg.exposure[b.Exposure]; !ok {
				add("%s: exposure %q is not declared under exposures", where, b.Exposure)
			}
		}
		if b.Interval != "" {
			switch interval, err := time.ParseDuration(b.Interval); {
			case err != nil:
				add("%s: interval %q: %v", where, b.Interval, err)
			case interval < MinInterval || interval > MaxInterval:
				add("%s: interval %s is outside %s..%s", where, interval, MinInterval, MaxInterval)
			default:
				bundle.Interval = interval
			}
		}
		if b.OnChangeCommand != nil {
			if len(b.OnChangeCommand) == 0 || b.OnChangeCommand[0] == "" {
				add("%s: onChangeCommand must start with a command to run", where)
			} else {
				bundle.OnChangeCommand = slices.Clone(b.OnChangeCommand)
			}
		}
		if len(b.Files) == 0 {
			add("%s: files must map at least one Secret key to a path", where)
		}
		for _, key := range slices.Sorted(maps.Keys(b.Files)) {
			f := b.Files[key]
			if !keyRE.MatchString(key) {
				add("%s: %q is not a valid Secret key", where, key)
				continue
			}
			file := File{Key: key, Path: f.Path, Mode: DefaultFileMode}
			switch {
			case f.Path == "":
				add("%s: key %q has no path", where, key)
			case !strings.HasPrefix(f.Path, "/"):
				add("%s: key %q: path %q must be absolute", where, key, f.Path)
			case strings.HasSuffix(f.Path, "/"):
				add("%s: key %q: path %q must name a file, not a directory", where, key, f.Path)
			default:
				if owner, dup := seenPath[f.Path]; dup {
					add("%s: key %q: path %q is already installed by %s", where, key, f.Path, owner)
					continue
				}
				seenPath[f.Path] = fmt.Sprintf("bundle %q", b.Name)
			}
			if f.Mode != "" {
				switch mode, err := strconv.ParseUint(f.Mode, 8, 32); {
				case err != nil || !strings.HasPrefix(f.Mode, "0"):
					add("%s: key %q: mode %q must be octal and start with 0, such as \"0640\"", where, key, f.Mode)
				case mode&^0o777 != 0:
					add("%s: key %q: mode %q must not set bits outside 0777", where, key, f.Mode)
				default:
					file.Mode = fs.FileMode(mode)
				}
			}
			bundle.Files = append(bundle.Files, file)
		}
		cfg.Bundles = append(cfg.Bundles, bundle)
	}

	if len(problems) > 0 {
		return nil, &Error{Problems: problems}
	}
	return cfg, nil
}
