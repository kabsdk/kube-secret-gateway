// Package gwtest is a fake kube-secret-gateway for tests.
//
// It reproduces the parts of the real server's contract that a client depends
// on, and nothing else: Basic Auth per exposure, the canonical bundle body
// (sorted keys, base64 values, no whitespace), an ETag that is HMAC-SHA256 of
// that body keyed with the Secret's UID, 304 for a matching If-None-Match, and
// the statuses the server gives when a Secret is not in the expected state.
//
// Keeping the ETag scheme identical matters: a test that rotates a value here
// exercises the same tag change a real gateway would produce.
package gwtest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
)

// Exposure is one exposure of the fake gateway.
type Exposure struct {
	Username string
	Password string
	// Values are the Secret's keys as the exposure serves them.
	Values map[string][]byte
	// UID stands in for the Kubernetes Secret UID that keys the ETag. Changing
	// it is how a test recreates the Secret.
	UID string
	// Status, when not 0, is returned instead of the bundle, for testing how a
	// client reacts to 401, 404 or 503.
	Status int
}

// Gateway is a running fake. Close it when the test ends.
type Gateway struct {
	server *httptest.Server

	mu        sync.Mutex
	exposures map[string]*Exposure
	requests  int
	notMod    int
}

// New starts a fake gateway. URL returns its base URL.
func New() *Gateway {
	g := &Gateway{exposures: make(map[string]*Exposure)}
	g.server = httptest.NewServer(http.HandlerFunc(g.serve))
	return g
}

func (g *Gateway) Close() { g.server.Close() }

// URL is the base URL to configure a client with.
func (g *Gateway) URL() string { return g.server.URL }

// Set installs or replaces an exposure.
func (g *Gateway) Set(name string, e Exposure) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e.UID == "" {
		e.UID = "uid-" + name
	}
	g.exposures[name] = &e
}

// Rotate replaces some of an exposure's values, as a renewal would.
func (g *Gateway) Rotate(name string, values map[string][]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.exposures[name]
	if e == nil {
		panic("gwtest: rotating unknown exposure " + name)
	}
	if e.Values == nil {
		e.Values = make(map[string][]byte)
	}
	maps.Copy(e.Values, values)
}

// Remove deletes one key from an exposure.
func (g *Gateway) Remove(name, key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.exposures[name].Values, key)
}

// SetStatus makes an exposure answer with status instead of a bundle. Zero
// restores normal service.
func (g *Gateway) SetStatus(name string, status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.exposures[name].Status = status
}

// Requests is how many requests the fake has answered, and how many of those
// were 304. A client that polls correctly turns almost all of them into 304.
func (g *Gateway) Requests() (total, notModified int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests, g.notMod
}

// ETag is the tag the fake would return for an exposure's current contents.
func (g *Gateway) ETag(name string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.exposures[name]
	return etag(body(e.Values), e.UID)
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.requests++
	g.mu.Unlock()

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	name, ok := strings.CutPrefix(r.URL.EscapedPath(), "/bundles/")
	if !ok || name == "" || strings.Contains(name, "/") {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	g.mu.Lock()
	e := g.exposures[name]
	g.mu.Unlock()
	// As on the real gateway, an unknown exposure is a plain 404.
	if e == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if e.Status != 0 {
		http.Error(w, http.StatusText(e.Status), e.Status)
		return
	}
	user, pass, hasAuth := r.BasicAuth()
	if !hasAuth || user != e.Username || pass != e.Password {
		w.Header().Set("WWW-Authenticate", `Basic realm="kube-secret-gateway"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	payload := body(e.Values)
	tag := etag(payload, e.UID)
	w.Header().Set("ETag", tag)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if match := r.Header.Get("If-None-Match"); match != "" && matches(match, tag) {
		g.mu.Lock()
		g.notMod++
		g.mu.Unlock()
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(payload)
	}
}

// body is the canonical bundle body: keys sorted, values base64, no
// whitespace. The real server builds the same bytes, which is what makes the
// ETag reproducible across replicas.
func body(values map[string][]byte) []byte {
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range slices.Sorted(maps.Keys(values)) {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:%q", k, base64.StdEncoding.EncodeToString(values[k]))
	}
	b.WriteByte('}')
	return []byte(b.String())
}

func etag(payload []byte, uid string) string {
	mac := hmac.New(sha256.New, []byte(uid))
	mac.Write(payload)
	return `"hmac-sha256:` + hex.EncodeToString(mac.Sum(nil)) + `"`
}

func matches(header, tag string) bool {
	for candidate := range strings.SplitSeq(header, ",") {
		c := strings.TrimSpace(candidate)
		if c == "*" || strings.TrimPrefix(c, "W/") == tag {
			return true
		}
	}
	return false
}
