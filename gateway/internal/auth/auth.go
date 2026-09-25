// Package auth verifies client credentials against the data of a Kubernetes
// Secret. Credentials are never part of the configuration; they are read from
// the current, watched state of the authentication Secret on every request,
// so rotating the Secret takes effect without a restart.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
)

// Realm is the HTTP authentication realm announced to clients.
const Realm = "kube-secret-gateway"

// Keys read from a basicAuth Secret.
const (
	UsernameKey = "username"
	PasswordKey = "password"
)

var (
	// ErrMissingUsername means the Secret lacks a non-empty "username" key.
	ErrMissingUsername = errors.New(`authentication Secret has no non-empty "username" key`)
	// ErrMissingPassword means the Secret lacks a non-empty "password" key.
	ErrMissingPassword = errors.New(`authentication Secret has no non-empty "password" key`)
)

// Basic verifies HTTP Basic credentials. It holds only SHA-256 digests of the
// expected username and password; comparing fixed-size digests keeps the
// comparison constant-time regardless of the presented credentials' lengths.
type Basic struct {
	username [sha256.Size]byte
	password [sha256.Size]byte
}

// NewBasic reads the expected credentials from Secret data. Empty values are
// treated as missing so that an empty password can never be accepted.
func NewBasic(data map[string][]byte) (*Basic, error) {
	username, password := data[UsernameKey], data[PasswordKey]
	if len(username) == 0 {
		return nil, ErrMissingUsername
	}
	if len(password) == 0 {
		return nil, ErrMissingPassword
	}
	return &Basic{username: sha256.Sum256(username), password: sha256.Sum256(password)}, nil
}

// Verify reports whether the request contains the expected Basic Auth
// credentials.
func (b *Basic) Verify(r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return b.matches(username, password)
}

func (b *Basic) matches(username, password string) bool {
	u := sha256.Sum256([]byte(username))
	p := sha256.Sum256([]byte(password))
	// Both comparisons always run and are combined without short-circuiting,
	// so timing reveals neither which part was wrong nor how much matched.
	return subtle.ConstantTimeCompare(u[:], b.username[:])&subtle.ConstantTimeCompare(p[:], b.password[:]) == 1
}

// Challenge returns the HTTP Basic authentication challenge.
func (b *Basic) Challenge() string {
	return `Basic realm="` + Realm + `"`
}
