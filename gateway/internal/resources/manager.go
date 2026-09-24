// Package resources maintains an in-memory, continuously updated view of an
// explicit set of Kubernetes Secrets.
//
// Every distinct Secret gets exactly one goroutine, which
//
//   - lists the Secret by exact name to establish its current state,
//   - watches it by exact name, starting at the listed resourceVersion,
//   - periodically fetches it directly and corrects the cache on drift, and
//   - after any watch failure resynchronizes with a fresh list before
//     watching again, retrying with capped, jittered exponential backoff.
//
// That goroutine is the only writer of its Secret's state, so list results,
// watch events and reconciliation results are applied strictly in order.
// Readers (HTTP handlers, metrics collectors) receive immutable snapshots and
// never cause Kubernetes API requests. Secret data is held only in memory.
package resources

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"kube-secret-gateway/internal/exposure"
)

// Client is the Kubernetes API surface the Manager needs. Implementations
// must restrict list and watch requests to the exact Secret name (field
// selector metadata.name=<name>) within the given namespace, so that RBAC
// rules scoped with resourceNames apply and no other Secret is requested.
type Client interface {
	ListSecret(ctx context.Context, ref exposure.SecretRef) (*corev1.SecretList, error)
	WatchSecret(ctx context.Context, ref exposure.SecretRef, resourceVersion string, timeout time.Duration) (watch.Interface, error)
	GetSecret(ctx context.Context, ref exposure.SecretRef) (*corev1.Secret, error)
}

// Secret is an immutable snapshot of one watched Secret.
type Secret struct {
	// Present reports whether the Secret currently exists. It is false both
	// when the Secret is known to be absent and when its state has not been
	// established yet.
	Present bool
	// Synced reports whether the state has been established at least once.
	Synced bool
	// Data is the Secret's data, or nil unless Present. It is shared between
	// readers and must not be modified.
	Data            map[string][]byte
	ResourceVersion string
	// UID identifies this incarnation of the Secret: it stays the same across
	// updates and changes when the Secret is deleted and created again.
	UID types.UID
}

// Status describes the synchronization state of one watched Secret.
type Status struct {
	Ref            exposure.SecretRef
	Present        bool
	Synced         bool
	WatchConnected bool
	// LastSuccessfulSync is the last time the full state was retrieved from
	// the API (list or reconciliation); zero if never.
	LastSuccessfulSync time.Time
	WatchErrors        uint64
	SyncErrors         uint64
}

// Options tunes a Manager. Zero values select the defaults.
type Options struct {
	// ReconcileInterval is how often each Secret is fetched directly to
	// correct state a watch may have missed. Default 5m.
	ReconcileInterval time.Duration
	// RequestTimeout bounds each list and get request. Default 30s.
	RequestTimeout time.Duration
	// WatchTimeout is the base server-side watch timeout; each watch uses a
	// random value in [WatchTimeout, 2*WatchTimeout). Default 5m.
	WatchTimeout time.Duration
	// InitialBackoff and MaxBackoff bound the retry delay after failures.
	// Defaults 1s and 30s.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// StableWatchDuration is how long a watch must stay open for the retry
	// backoff to reset. Default 1m.
	StableWatchDuration time.Duration
	Logger              *slog.Logger
}

func (o Options) withDefaults() Options {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.ReconcileInterval, 5*time.Minute)
	def(&o.RequestTimeout, 30*time.Second)
	def(&o.WatchTimeout, 5*time.Minute)
	def(&o.InitialBackoff, time.Second)
	def(&o.MaxBackoff, 30*time.Second)
	def(&o.StableWatchDuration, time.Minute)
	o.MaxBackoff = max(o.MaxBackoff, o.InitialBackoff)
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return o
}

// watchDeadlineGrace is added to the server-side watch timeout to form a
// client-side deadline, in case the server's close never reaches us.
const watchDeadlineGrace = 30 * time.Second

// Manager keeps the state of a fixed set of Secrets current.
type Manager struct {
	client    Client
	opts      Options
	resources map[exposure.SecretRef]*resource
	sorted    []*resource

	started     atomic.Bool
	pending     atomic.Int64
	initialized chan struct{}
	wg          sync.WaitGroup
}

// NewManager returns a Manager for refs. Duplicate references share a single
// state entry and a single watcher.
func NewManager(client Client, refs []exposure.SecretRef, opts Options) *Manager {
	opts = opts.withDefaults()
	m := &Manager{
		client:      client,
		opts:        opts,
		resources:   make(map[exposure.SecretRef]*resource, len(refs)),
		initialized: make(chan struct{}),
	}
	for _, ref := range refs {
		if _, dup := m.resources[ref]; dup {
			continue
		}
		r := &resource{
			ref:    ref,
			log:    opts.Logger.With("namespace", ref.Namespace, "secret", ref.Name),
			synced: make(chan struct{}),
		}
		m.resources[ref] = r
		m.sorted = append(m.sorted, r)
	}
	slices.SortFunc(m.sorted, func(a, b *resource) int { return a.ref.Compare(b.ref) })
	m.pending.Store(int64(len(m.sorted)))
	if len(m.sorted) == 0 {
		close(m.initialized)
	}
	return m
}

// Start launches one watcher per Secret. They run until ctx is cancelled;
// use Wait to block until they have exited. Start does not block and is a
// no-op when called again.
func (m *Manager) Start(ctx context.Context) {
	if !m.started.CompareAndSwap(false, true) {
		return
	}
	for _, r := range m.sorted {
		m.wg.Add(1)
		go m.run(ctx, r)
	}
}

// Wait blocks until all watchers have exited after their context ended.
func (m *Manager) Wait() { m.wg.Wait() }

// Initialized reports whether the initial synchronization has been attempted
// for every Secret. Individual attempts may have failed; that is visible per
// Secret through Status and does not keep the Manager uninitialized.
func (m *Manager) Initialized() bool {
	select {
	case <-m.initialized:
		return true
	default:
		return false
	}
}

// WaitInitialized blocks until Initialized is true or ctx ends.
func (m *Manager) WaitInitialized(ctx context.Context) error {
	select {
	case <-m.initialized:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitSynced blocks until the state of ref has been established once, that
// is, until the Secret is known to be present or absent, or ctx ends.
func (m *Manager) WaitSynced(ctx context.Context, ref exposure.SecretRef) error {
	r, ok := m.resources[ref]
	if !ok {
		return fmt.Errorf("secret %s is not managed", ref)
	}
	select {
	case <-r.synced:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Secret returns the current snapshot of ref. Unknown references are
// reported as not present. It never performs API requests.
func (m *Manager) Secret(ref exposure.SecretRef) Secret {
	r, ok := m.resources[ref]
	if !ok {
		return Secret{}
	}
	return r.snapshot()
}

// Statuses returns the synchronization state of every Secret, sorted by
// reference.
func (m *Manager) Statuses() []Status {
	out := make([]Status, 0, len(m.sorted))
	for _, r := range m.sorted {
		out = append(out, r.status())
	}
	return out
}

func (m *Manager) initDone() {
	if m.pending.Add(-1) == 0 {
		close(m.initialized)
	}
}

func (m *Manager) run(ctx context.Context, r *resource) {
	defer m.wg.Done()
	// Covers exiting before the first attempt, so waiters are released.
	defer r.initOnce.Do(m.initDone)

	bo := backoff{initial: m.opts.InitialBackoff, max: m.opts.MaxBackoff}
	for ctx.Err() == nil {
		healthy := m.cycle(ctx, r)
		if ctx.Err() != nil {
			return
		}
		if healthy {
			bo.reset()
			continue
		}
		delay := bo.next()
		r.log.Debug("retrying synchronization", "delay", delay)
		if !sleep(ctx, delay) {
			return
		}
	}
}

// cycle runs one list-then-watch round. It reports whether the watch stayed
// open long enough to count as healthy, in which case the next round starts
// without delay.
func (m *Manager) cycle(ctx context.Context, r *resource) (healthy bool) {
	defer func() {
		// Last line of defence: a bug handling one Secret must not take down
		// the process or the other watchers. Only the panic's type is logged,
		// never its value, which could conceivably contain object data.
		if p := recover(); p != nil {
			r.initOnce.Do(m.initDone)
			r.recordWatchError()
			r.log.Error("recovered from panic while synchronizing Secret",
				"panic_type", fmt.Sprintf("%T", p), "stack", string(debug.Stack()))
			healthy = false
		}
	}()

	rv, err := m.list(ctx, r)
	r.initOnce.Do(m.initDone)
	if err != nil {
		return false
	}
	start := time.Now()
	m.watch(ctx, r, rv)
	return time.Since(start) >= m.opts.StableWatchDuration
}

// list establishes the current state with an exact-name list and returns the
// list's resourceVersion, from which the following watch starts.
func (m *Manager) list(ctx context.Context, r *resource) (string, error) {
	lctx, cancel := context.WithTimeout(ctx, m.opts.RequestTimeout)
	defer cancel()

	list, err := m.client.ListSecret(lctx, r.ref)
	if err == nil && list == nil {
		err = errors.New("client returned no list")
	}
	if err != nil {
		if ctx.Err() == nil {
			r.recordSyncError()
			r.log.Warn("listing Secret failed", "error", describeError(err))
		}
		return "", err
	}

	var found *corev1.Secret
	for i := range list.Items {
		if r.matches(&list.Items[i]) {
			found = &list.Items[i]
			break
		}
	}
	if found == nil && len(list.Items) > 0 {
		// Only possible if the field selector was ignored. Concluding the
		// Secret is absent could be wrong, so keep the current state.
		r.recordSyncError()
		r.log.Warn("list returned only unexpected objects; keeping current state", "items", len(list.Items))
		return "", errors.New("list returned unexpected objects")
	}
	prev, cur := r.store(found, true)
	logSync(r, "list", prev, cur)
	return list.ResourceVersion, nil
}

func (m *Manager) watch(ctx context.Context, r *resource, resourceVersion string) {
	timeout := m.opts.WatchTimeout + rand.N(m.opts.WatchTimeout)
	wctx, cancel := context.WithTimeout(ctx, timeout+watchDeadlineGrace)
	defer cancel()

	w, err := m.client.WatchSecret(wctx, r.ref, resourceVersion, timeout)
	if err == nil && w == nil {
		err = errors.New("client returned no watch")
	}
	if err != nil {
		if ctx.Err() == nil {
			r.recordWatchError()
			r.log.Warn("starting watch failed", "error", describeError(err))
		}
		return
	}
	defer w.Stop()
	r.setConnected(true)
	defer r.setConnected(false)
	r.log.Debug("watch established", "resource_version", resourceVersion)

	reconcile := time.NewTimer(jitter(m.opts.ReconcileInterval))
	defer reconcile.Stop()
	events := w.ResultChan()
	for {
		select {
		case <-wctx.Done():
			if ctx.Err() == nil {
				r.log.Debug("watch deadline reached; resynchronizing")
			}
			return
		case <-reconcile.C:
			if !m.reconcile(ctx, r) {
				return
			}
			reconcile.Reset(jitter(m.opts.ReconcileInterval))
		case ev, ok := <-events:
			if !ok {
				r.log.Debug("watch closed; resynchronizing")
				return
			}
			if !m.handleEvent(r, ev) {
				return
			}
		}
	}
}

// handleEvent applies one watch event. It returns false when the watch must
// be abandoned and the state resynchronized from a fresh list. Anything
// unexpected leads to a resync rather than to guessing, and objects are never
// logged, only their type.
func (m *Manager) handleEvent(r *resource, ev watch.Event) bool {
	switch ev.Type {
	case watch.Added, watch.Modified, watch.Deleted:
		s, ok := ev.Object.(*corev1.Secret)
		if !ok || s == nil {
			r.recordWatchError()
			r.log.Warn("watch event carried an unexpected object; resynchronizing",
				"event", ev.Type, "object_type", fmt.Sprintf("%T", ev.Object))
			return false
		}
		if !r.matches(s) {
			r.recordWatchError()
			r.log.Warn("watch event for a different Secret; resynchronizing",
				"event", ev.Type, "object_namespace", s.Namespace, "object_name", s.Name)
			return false
		}
		rv := s.ResourceVersion
		if ev.Type == watch.Deleted {
			s = nil
		}
		_, cur := r.store(s, false)
		level := slog.LevelInfo
		if !cur.Present {
			level = slog.LevelWarn
		}
		r.log.Log(context.Background(), level, "Secret changed", "event", ev.Type, "present", cur.Present, "resource_version", rv)
		return true
	case watch.Bookmark:
		return true
	case watch.Error:
		r.recordWatchError()
		r.log.Warn("watch reported an error; resynchronizing", "error", describeWatchError(ev.Object))
		return false
	default:
		r.recordWatchError()
		r.log.Warn("unknown watch event type; resynchronizing", "event", ev.Type)
		return false
	}
}

// reconcile fetches the Secret directly and corrects the cache if the watch
// has missed something. It returns false if drift was found, so that the
// watch, which evidently cannot be trusted, is replaced after a fresh list.
func (m *Manager) reconcile(ctx context.Context, r *resource) bool {
	gctx, cancel := context.WithTimeout(ctx, m.opts.RequestTimeout)
	defer cancel()

	s, err := m.client.GetSecret(gctx, r.ref)
	switch {
	case err != nil && apierrors.IsNotFound(err):
		s = nil
	case err != nil:
		if ctx.Err() == nil {
			r.recordSyncError()
			r.log.Warn("reconciliation failed; keeping watch", "error", describeError(err))
		}
		return true
	case s == nil || !r.matches(s):
		r.recordSyncError()
		r.log.Warn("reconciliation returned an unexpected object; keeping watch")
		return true
	}

	prev, cur := r.store(s, true)
	if prev.Present != cur.Present || prev.ResourceVersion != cur.ResourceVersion {
		r.log.Warn("reconciliation corrected stale state; restarting watch",
			"present", cur.Present, "resource_version", cur.ResourceVersion, "previous_resource_version", prev.ResourceVersion)
		return false
	}
	r.log.Debug("reconciliation confirmed cached state", "resource_version", cur.ResourceVersion)
	return true
}

func logSync(r *resource, source string, prev, cur Secret) {
	if prev.Synced && prev.Present == cur.Present && prev.ResourceVersion == cur.ResourceVersion {
		r.log.Debug("Secret state confirmed", "source", source, "resource_version", cur.ResourceVersion)
		return
	}
	if !cur.Present {
		r.log.Warn("Secret is absent", "source", source)
		return
	}
	r.log.Info("Secret synchronized", "source", source, "resource_version", cur.ResourceVersion)
}

// resource is the state of one Secret. Only its watcher goroutine writes it.
type resource struct {
	ref        exposure.SecretRef
	log        *slog.Logger
	initOnce   sync.Once
	syncedOnce sync.Once
	synced     chan struct{} // closed once the state is first established

	mu          sync.RWMutex
	secret      Secret
	connected   bool
	lastSync    time.Time
	watchErrors uint64
	syncErrors  uint64
}

func (r *resource) matches(s *corev1.Secret) bool {
	return s.Name == r.ref.Name && (s.Namespace == "" || s.Namespace == r.ref.Namespace)
}

// store replaces the cached state with obj, or with "absent" if obj is nil.
// The data is deep-copied so the cache never aliases client-owned memory.
func (r *resource) store(obj *corev1.Secret, fullSync bool) (prev, cur Secret) {
	cur = Secret{Synced: true}
	if obj != nil {
		cur.Present = true
		cur.ResourceVersion = obj.ResourceVersion
		cur.UID = obj.UID
		cur.Data = make(map[string][]byte, len(obj.Data))
		for k, v := range obj.Data {
			cur.Data[k] = slices.Clone(v)
		}
	}
	r.mu.Lock()
	prev = r.secret
	r.secret = cur
	if fullSync {
		r.lastSync = time.Now()
	}
	r.mu.Unlock()
	r.syncedOnce.Do(func() { close(r.synced) })
	return prev, cur
}

func (r *resource) snapshot() Secret {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.secret
}

func (r *resource) status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Status{
		Ref:                r.ref,
		Present:            r.secret.Present,
		Synced:             r.secret.Synced,
		WatchConnected:     r.connected,
		LastSuccessfulSync: r.lastSync,
		WatchErrors:        r.watchErrors,
		SyncErrors:         r.syncErrors,
	}
}

func (r *resource) setConnected(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connected = v
}

func (r *resource) recordWatchError() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.watchErrors++
}

func (r *resource) recordSyncError() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncErrors++
}

// backoff is capped exponential backoff with jitter.
type backoff struct {
	initial, max, current time.Duration
}

func (b *backoff) next() time.Duration {
	if b.current == 0 {
		b.current = b.initial
	} else {
		b.current = min(2*b.current, b.max)
	}
	// Spread retries over [current/2, current] so that watchers failing
	// together do not retry in lockstep.
	half := b.current / 2
	return half + rand.N(b.current-half+1)
}

func (b *backoff) reset() { b.current = 0 }

// jitter spreads d by ±10% so reconciliations of many Secrets drift apart.
func jitter(d time.Duration) time.Duration {
	return d - d/10 + rand.N(d/5+1)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// describeError renders a Kubernetes client error for logging. API status
// errors are reduced to code, reason and message. All text is cut at the
// first '{': some decoding errors embed the raw response body, which for a
// Secret would contain its data.
func describeError(err error) string {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		s := status.Status()
		return redact(fmt.Sprintf("%d %s: %s", s.Code, s.Reason, s.Message))
	}
	return redact(err.Error())
}

// describeWatchError renders the object of a watch ERROR event. Unlike
// apierrors.FromObject it never formats a non-Status object.
func describeWatchError(obj runtime.Object) string {
	status, ok := obj.(*metav1.Status)
	if !ok || status == nil {
		return fmt.Sprintf("unexpected error object of type %T", obj)
	}
	return describeError(&apierrors.StatusError{ErrStatus: *status})
}

func redact(s string) string {
	if i := strings.IndexByte(s, '{'); i >= 0 {
		s = s[:i] + "[redacted]"
	}
	const maxLen = 512
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "") + "..."
	}
	return s
}
