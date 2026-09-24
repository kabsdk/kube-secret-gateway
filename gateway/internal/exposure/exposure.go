// Package exposure defines the source-independent model of what the gateway
// serves: named HTTP exposures, each backed by exactly one Kubernetes Secret
// and protected by an allow-list of client networks and an authentication
// Secret.
//
// The model carries no YAML, HTTP or client-go concerns. The YAML loader in
// package config is one producer of []Exposure; another source (a custom
// resource, for example) could produce the same values without changes to the
// HTTP, authentication, resource watching or metrics layers.
package exposure

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// SecretRef identifies a Kubernetes Secret. Both fields are always set: the
// gateway never falls back to the namespace it happens to run in.
type SecretRef struct {
	Namespace string
	Name      string
}

func (r SecretRef) String() string { return r.Namespace + "/" + r.Name }

// Compare orders references by namespace, then name.
func (r SecretRef) Compare(o SecretRef) int {
	return cmp.Or(cmp.Compare(r.Namespace, o.Namespace), cmp.Compare(r.Name, o.Name))
}

// AuthType selects how clients of an exposure authenticate.
type AuthType string

// AuthBasic is HTTP Basic authentication against the "username" and
// "password" keys of a Kubernetes Secret.
const AuthBasic AuthType = "basicAuth"

// Auth describes how clients of an exposure authenticate. Credentials always
// live in a Kubernetes Secret, never in configuration.
type Auth struct {
	Type      AuthType
	SecretRef SecretRef
}

// Exposure is one HTTP exposure: GET /secrets/{Name}/{key} serves key from
// the Source Secret, subject to Keys, AllowedCIDRs and Auth.
type Exposure struct {
	// Name is the URL path segment. It is independent of the Secret's
	// namespace, which never appears in URLs.
	Name         string
	Source       SecretRef
	AllowedCIDRs []netip.Prefix
	Auth         Auth
	Keys         KeyFilter
}

// AllowsClient reports whether addr is inside one of the allowed networks.
// IPv4-mapped IPv6 addresses match the corresponding IPv4 networks.
func (e *Exposure) AllowsClient(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range e.AllowedCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ReferencedSecrets returns the sorted, deduplicated set of Secrets the
// exposures depend on: source and authentication Secrets alike.
func ReferencedSecrets(exposures []Exposure) []SecretRef {
	seen := make(map[SecretRef]struct{})
	var refs []SecretRef
	for i := range exposures {
		for _, ref := range []SecretRef{exposures[i].Source, exposures[i].Auth.SecretRef} {
			if _, ok := seen[ref]; !ok {
				seen[ref] = struct{}{}
				refs = append(refs, ref)
			}
		}
	}
	slices.SortFunc(refs, SecretRef.Compare)
	return refs
}

type keyMode uint8

const (
	allKeys keyMode = iota
	includeKeys
	excludeKeys
)

// KeyFilter decides which keys of the backing Secret an exposure serves. The
// zero value serves every key.
type KeyFilter struct {
	mode keyMode
	set  map[string]struct{}
	list []string
}

// IncludeKeys returns a filter that serves only keys, and treats each of them
// as required: a missing included key is an operational failure rather than
// an ordinary "not found". Duplicates are ignored.
func IncludeKeys(keys ...string) KeyFilter { return newKeyFilter(includeKeys, keys) }

// ExcludeKeys returns a filter that serves every key except keys, which behave
// as if they did not exist. Duplicates are ignored.
func ExcludeKeys(keys ...string) KeyFilter { return newKeyFilter(excludeKeys, keys) }

func newKeyFilter(mode keyMode, keys []string) KeyFilter {
	f := KeyFilter{mode: mode, set: make(map[string]struct{}, len(keys))}
	for _, k := range keys {
		if _, dup := f.set[k]; dup {
			continue
		}
		f.set[k] = struct{}{}
		f.list = append(f.list, k)
	}
	return f
}

// Exposes reports whether key may be served through the exposure.
func (f KeyFilter) Exposes(key string) bool {
	_, listed := f.set[key]
	switch f.mode {
	case includeKeys:
		return listed
	case excludeKeys:
		return !listed
	default:
		return true
	}
}

// Required reports whether key is explicitly expected to exist.
func (f KeyFilter) Required(key string) bool {
	_, listed := f.set[key]
	return f.mode == includeKeys && listed
}

// RequiredKeys returns the explicitly expected keys in configuration order.
func (f KeyFilter) RequiredKeys() []string {
	if f.mode != includeKeys {
		return nil
	}
	return slices.Clone(f.list)
}

// ValidateName checks an exposure name. Names follow Kubernetes object naming
// (RFC 1123 subdomain), so a name defaulted from a Secret name is always valid
// and names never need percent-encoding in a URL.
func ValidateName(name string) error {
	return validationErr(validation.IsDNS1123Subdomain(name))
}

// ValidateSecretName checks a Kubernetes Secret name.
func ValidateSecretName(name string) error {
	return validationErr(validation.IsDNS1123Subdomain(name))
}

// ValidateNamespace checks a Kubernetes namespace name.
func ValidateNamespace(namespace string) error {
	return validationErr(validation.IsDNS1123Label(namespace))
}

// ValidateKey checks a Secret data key. Valid keys consist of [-._a-zA-Z0-9],
// so they can never contain a path separator or require percent-encoding.
func ValidateKey(key string) error {
	return validationErr(validation.IsConfigMapKey(key))
}

func validationErr(problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

// ParsePrefix parses a CIDR strictly. The address must be the network address
// (no host bits set) so that a typo such as 10.0.0.1/8 cannot silently grant a
// much wider range than intended, and IPv4 networks must use IPv4 notation.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: write IPv4 networks in IPv4 notation", s)
	}
	if m := p.Masked(); m != p {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: host bits are set (the network is %s)", s, m)
	}
	return p, nil
}
