// Package kubetest provides an in-memory, exact-name Secret API implementing
// resources.Client, with call recording and failure injection for tests.
package kubetest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"kube-secret-gateway/internal/exposure"
)

// Verb identifies a recorded API call.
type Verb string

const (
	List  Verb = "list"
	Watch Verb = "watch"
	Get   Verb = "get"
)

// Call is one recorded API call.
type Call struct {
	Verb Verb
	Ref  exposure.SecretRef
	// ResourceVersion is the version a watch started from.
	ResourceVersion string
}

type historyEntry struct {
	ref exposure.SecretRef
	rv  int64
	ev  watch.Event
}

// FakeAPI is a concurrency-safe fake of the exact-name Secret API. Watches
// behave like the real API: a watch started at resourceVersion N receives
// every recorded change after N, so no change is lost between list and watch.
type FakeAPI struct {
	mu        sync.Mutex
	rv        int64
	secrets   map[exposure.SecretRef]*corev1.Secret
	watches   map[exposure.SecretRef][]*fakeWatch
	history   []historyEntry
	errs      map[Verb]map[exposure.SecretRef]error
	overrides map[exposure.SecretRef]*corev1.SecretList
	calls     []Call
}

// New returns an empty FakeAPI.
func New() *FakeAPI {
	return &FakeAPI{
		rv:        100,
		secrets:   make(map[exposure.SecretRef]*corev1.Secret),
		watches:   make(map[exposure.SecretRef][]*fakeWatch),
		errs:      make(map[Verb]map[exposure.SecretRef]error),
		overrides: make(map[exposure.SecretRef]*corev1.SecretList),
	}
}

// ListSecret implements resources.Client.
func (f *FakeAPI) ListSecret(_ context.Context, ref exposure.SecretRef) (*corev1.SecretList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Verb: List, Ref: ref})
	if err := f.errs[List][ref]; err != nil {
		return nil, err
	}
	if l, ok := f.overrides[ref]; ok {
		return l.DeepCopy(), nil
	}
	list := &corev1.SecretList{ListMeta: metav1.ListMeta{ResourceVersion: strconv.FormatInt(f.rv, 10)}}
	if s, ok := f.secrets[ref]; ok {
		list.Items = append(list.Items, *s.DeepCopy())
	}
	return list, nil
}

// WatchSecret implements resources.Client.
func (f *FakeAPI) WatchSecret(_ context.Context, ref exposure.SecretRef, resourceVersion string, _ time.Duration) (watch.Interface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Verb: Watch, Ref: ref, ResourceVersion: resourceVersion})
	if err := f.errs[Watch][ref]; err != nil {
		return nil, err
	}
	from, err := strconv.ParseInt(resourceVersion, 10, 64)
	if err != nil {
		from = f.rv
	}
	w := newFakeWatch()
	for _, h := range f.history {
		if h.ref == ref && h.rv > from {
			select {
			case w.ch <- watch.Event{Type: h.ev.Type, Object: h.ev.Object.DeepCopyObject()}:
			default:
				panic("kubetest: too many events to replay into a new watch")
			}
		}
	}
	f.watches[ref] = append(slices.DeleteFunc(f.watches[ref], func(w *fakeWatch) bool { return !w.open() }), w)
	return w, nil
}

// GetSecret implements resources.Client.
func (f *FakeAPI) GetSecret(_ context.Context, ref exposure.SecretRef) (*corev1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Verb: Get, Ref: ref})
	if err := f.errs[Get][ref]; err != nil {
		return nil, err
	}
	s, ok := f.secrets[ref]
	if !ok {
		return nil, errors.NewNotFound(schema.GroupResource{Resource: "secrets"}, ref.Name)
	}
	return s.DeepCopy(), nil
}

// Apply creates or updates a Secret and notifies watches. It returns the new
// resourceVersion.
func (f *FakeAPI) Apply(ref exposure.SecretRef, data map[string][]byte) string {
	return f.apply(ref, data, true)
}

// ApplySilently changes a Secret without any watch event, simulating an event
// the watch missed.
func (f *FakeAPI) ApplySilently(ref exposure.SecretRef, data map[string][]byte) string {
	return f.apply(ref, data, false)
}

// Delete removes a Secret and notifies watches.
func (f *FakeAPI) Delete(ref exposure.SecretRef) { f.delete(ref, true) }

// DeleteSilently removes a Secret without any watch event.
func (f *FakeAPI) DeleteSilently(ref exposure.SecretRef) { f.delete(ref, false) }

func (f *FakeAPI) apply(ref exposure.SecretRef, data map[string][]byte, notify bool) string {
	f.mu.Lock()
	f.rv++
	rv := f.rv
	evType := watch.Modified
	uid := types.UID(fmt.Sprintf("uid-%d", rv))
	if existing, ok := f.secrets[ref]; ok {
		uid = existing.UID
	} else {
		evType = watch.Added
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ref.Namespace,
			Name:            ref.Name,
			ResourceVersion: strconv.FormatInt(rv, 10),
			UID:             uid,
		},
		Data: cloneData(data),
	}
	f.secrets[ref] = s
	targets := f.record(ref, rv, watch.Event{Type: evType, Object: s}, notify)
	f.mu.Unlock()
	f.deliver(targets, watch.Event{Type: evType, Object: s.DeepCopy()})
	return strconv.FormatInt(rv, 10)
}

func (f *FakeAPI) delete(ref exposure.SecretRef, notify bool) {
	f.mu.Lock()
	existing, ok := f.secrets[ref]
	if !ok {
		f.mu.Unlock()
		return
	}
	delete(f.secrets, ref)
	f.rv++
	gone := existing.DeepCopy()
	gone.ResourceVersion = strconv.FormatInt(f.rv, 10)
	targets := f.record(ref, f.rv, watch.Event{Type: watch.Deleted, Object: gone}, notify)
	f.mu.Unlock()
	f.deliver(targets, watch.Event{Type: watch.Deleted, Object: gone.DeepCopy()})
}

// record must be called with f.mu held.
func (f *FakeAPI) record(ref exposure.SecretRef, rv int64, ev watch.Event, notify bool) []*fakeWatch {
	if !notify {
		return nil
	}
	f.history = append(f.history, historyEntry{ref: ref, rv: rv, ev: watch.Event{Type: ev.Type, Object: ev.Object.DeepCopyObject()}})
	return slices.Clone(f.watches[ref])
}

func (f *FakeAPI) deliver(targets []*fakeWatch, ev watch.Event) {
	for _, w := range targets {
		w.send(watch.Event{Type: ev.Type, Object: ev.Object.DeepCopyObject()})
	}
}

// SendEvent delivers an arbitrary event, possibly malformed, to the
// currently open watches of ref. It is not recorded in the history.
func (f *FakeAPI) SendEvent(ref exposure.SecretRef, ev watch.Event) {
	f.mu.Lock()
	targets := slices.Clone(f.watches[ref])
	f.mu.Unlock()
	for _, w := range targets {
		w.send(ev)
	}
}

// CloseWatches ends all open watches of ref, as a server disconnect would.
func (f *FakeAPI) CloseWatches(ref exposure.SecretRef) {
	f.mu.Lock()
	targets := f.watches[ref]
	delete(f.watches, ref)
	f.mu.Unlock()
	for _, w := range targets {
		w.closeResults()
	}
}

// SetError makes every call of verb for ref fail with err until it is reset
// with a nil error.
func (f *FakeAPI) SetError(verb Verb, ref exposure.SecretRef, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errs[verb] == nil {
		f.errs[verb] = make(map[exposure.SecretRef]error)
	}
	if err == nil {
		delete(f.errs[verb], ref)
	} else {
		f.errs[verb][ref] = err
	}
}

// SetListResult makes list calls for ref return list verbatim until it is
// reset with nil.
func (f *FakeAPI) SetListResult(ref exposure.SecretRef, list *corev1.SecretList) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if list == nil {
		delete(f.overrides, ref)
	} else {
		f.overrides[ref] = list.DeepCopy()
	}
}

// Calls returns all recorded calls in order.
func (f *FakeAPI) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// CallCount returns how often verb was called for ref.
func (f *FakeAPI) CallCount(verb Verb, ref exposure.SecretRef) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.Verb == verb && c.Ref == ref {
			n++
		}
	}
	return n
}

// TotalCalls returns the number of recorded calls.
func (f *FakeAPI) TotalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// OpenWatches returns how many watches of ref are open and not stopped.
func (f *FakeAPI) OpenWatches(ref exposure.SecretRef) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, w := range f.watches[ref] {
		if w.open() {
			n++
		}
	}
	return n
}

func cloneData(data map[string][]byte) map[string][]byte {
	if data == nil {
		return nil
	}
	out := maps.Clone(data)
	for k, v := range out {
		out[k] = slices.Clone(v)
	}
	return out
}

type fakeWatch struct {
	ch       chan watch.Event
	stopped  chan struct{}
	stopOnce sync.Once

	mu     sync.Mutex
	closed bool
}

func newFakeWatch() *fakeWatch {
	return &fakeWatch{ch: make(chan watch.Event, 128), stopped: make(chan struct{})}
}

func (w *fakeWatch) ResultChan() <-chan watch.Event { return w.ch }

func (w *fakeWatch) Stop() { w.stopOnce.Do(func() { close(w.stopped) }) }

func (w *fakeWatch) send(ev watch.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	select {
	case w.ch <- ev:
	case <-w.stopped:
	}
}

func (w *fakeWatch) closeResults() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
}

func (w *fakeWatch) open() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.stopped:
		return false
	default:
		return !w.closed
	}
}
