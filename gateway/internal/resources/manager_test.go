package resources_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"

	"kube-secret-gateway/internal/exposure"
	"kube-secret-gateway/internal/kubernetes/kubetest"
	"kube-secret-gateway/internal/resources"
)

var (
	certRef = exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}
	authRef = exposure.SecretRef{Namespace: "certificate-auth", Name: "creds"}
)

// fastOptions makes every retry nearly immediate and keeps reconciliation
// and watch expiry out of the way unless a test enables them.
func fastOptions() resources.Options {
	return resources.Options{
		ReconcileInterval:   time.Hour,
		RequestTimeout:      5 * time.Second,
		WatchTimeout:        time.Hour,
		InitialBackoff:      time.Millisecond,
		MaxBackoff:          5 * time.Millisecond,
		StableWatchDuration: time.Hour,
	}
}

func start(t *testing.T, api resources.Client, opts resources.Options, refs ...exposure.SecretRef) *resources.Manager {
	t.Helper()
	m := resources.NewManager(api, refs, opts)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(func() {
		cancel()
		m.Wait()
	})
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if err := m.WaitInitialized(waitCtx); err != nil {
		t.Fatalf("manager did not initialize: %v", err)
	}
	return m
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func status(m *resources.Manager, ref exposure.SecretRef) resources.Status {
	for _, st := range m.Statuses() {
		if st.Ref == ref {
			return st
		}
	}
	return resources.Status{}
}

func waitConnected(t *testing.T, m *resources.Manager, ref exposure.SecretRef) {
	t.Helper()
	eventually(t, "watch connected for "+ref.String(), func() bool { return status(m, ref).WatchConnected })
}

func waitVersion(t *testing.T, m *resources.Manager, ref exposure.SecretRef, rv string) {
	t.Helper()
	eventually(t, "resourceVersion "+rv, func() bool {
		s := m.Secret(ref)
		return s.Present && s.ResourceVersion == rv
	})
}

func waitAbsent(t *testing.T, m *resources.Manager, ref exposure.SecretRef) {
	t.Helper()
	eventually(t, "absent "+ref.String(), func() bool {
		s := m.Secret(ref)
		return s.Synced && !s.Present
	})
}

func data(kv ...string) map[string][]byte {
	out := make(map[string][]byte)
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = []byte(kv[i+1])
	}
	return out
}

func TestInitialSyncSecretExists(t *testing.T) {
	api := kubetest.New()
	rv := api.Apply(certRef, data("tls.crt", "CERT", "tls.key", "KEY"))
	m := start(t, api, fastOptions(), certRef)

	s := m.Secret(certRef)
	if !s.Present || !s.Synced || s.ResourceVersion != rv {
		t.Fatalf("snapshot = %+v, want present at %s", s, rv)
	}
	if string(s.Data["tls.crt"]) != "CERT" || string(s.Data["tls.key"]) != "KEY" {
		t.Fatalf("unexpected data")
	}
	st := status(m, certRef)
	if st.LastSuccessfulSync.IsZero() || st.SyncErrors != 0 || st.WatchErrors != 0 {
		t.Fatalf("status = %+v", st)
	}
	waitConnected(t, m, certRef)
}

func TestInitialSyncSecretMissing(t *testing.T) {
	api := kubetest.New()
	m := start(t, api, fastOptions(), certRef)

	s := m.Secret(certRef)
	if s.Present || !s.Synced || s.Data != nil {
		t.Fatalf("snapshot = %+v, want synced and absent", s)
	}
	// Missing is a legitimate state: the watcher keeps running.
	waitConnected(t, m, certRef)
	if st := status(m, certRef); st.SyncErrors != 0 || st.LastSuccessfulSync.IsZero() {
		t.Fatalf("a missing Secret is not a sync error: %+v", st)
	}
}

func TestMissingSecretLaterAdded(t *testing.T) {
	api := kubetest.New()
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	rv := api.Apply(certRef, data("tls.crt", "CERT"))
	waitVersion(t, m, certRef, rv)
	if got := string(m.Secret(certRef).Data["tls.crt"]); got != "CERT" {
		t.Fatalf("data = %q", got)
	}
	if n := api.CallCount(kubetest.List, certRef); n != 1 {
		t.Fatalf("the ADDED event must be applied from the watch, got %d lists", n)
	}
}

func TestModifiedUpdatesCache(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "OLD"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	rv := api.Apply(certRef, data("tls.crt", "NEW", "ca.crt", "CA"))
	waitVersion(t, m, certRef, rv)
	s := m.Secret(certRef)
	if string(s.Data["tls.crt"]) != "NEW" || string(s.Data["ca.crt"]) != "CA" {
		t.Fatal("cache not updated from MODIFIED event")
	}
}

func TestDeletedMarksAbsentAndDropsData(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	api.Delete(certRef)
	waitAbsent(t, m, certRef)
	s := m.Secret(certRef)
	if s.Data != nil || s.ResourceVersion != "" {
		t.Fatalf("stale data survived the delete: %+v", s)
	}
	if !status(m, certRef).WatchConnected {
		t.Fatal("a DELETED event must not break the watch")
	}
}

func TestSecretRecreatedAfterDeletion(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "FIRST"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	api.Delete(certRef)
	waitAbsent(t, m, certRef)
	rv := api.Apply(certRef, data("tls.crt", "SECOND"))
	waitVersion(t, m, certRef, rv)
	if got := string(m.Secret(certRef).Data["tls.crt"]); got != "SECOND" {
		t.Fatalf("data = %q", got)
	}
}

func TestWatchDisconnectReconnectsAfterRelist(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	api.CloseWatches(certRef)
	eventually(t, "second watch", func() bool { return api.CallCount(kubetest.Watch, certRef) == 2 && api.OpenWatches(certRef) == 1 })

	// Every watch must be preceded by a list of the same Secret.
	var verbs []string
	for _, c := range api.Calls() {
		verbs = append(verbs, string(c.Verb))
	}
	if got := strings.Join(verbs, ","); got != "list,watch,list,watch" {
		t.Fatalf("calls = %s, want list,watch,list,watch", got)
	}
	if st := status(m, certRef); st.WatchErrors != 0 {
		t.Fatalf("a clean disconnect is not a watch error: %+v", st)
	}
	// The new watch delivers events.
	rv := api.Apply(certRef, data("tls.crt", "NEW"))
	waitVersion(t, m, certRef, rv)
}

func TestChangesWhileDisconnectedAreResynchronized(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	// The watch cannot be re-established, and the change produces no event.
	api.SetError(kubetest.Watch, certRef, errors.New("connection refused"))
	api.CloseWatches(certRef)
	api.DeleteSilently(certRef)

	// The list before each watch attempt picks up the deletion.
	waitAbsent(t, m, certRef)
	eventually(t, "watch errors counted", func() bool { return status(m, certRef).WatchErrors >= 1 })
	if status(m, certRef).WatchConnected {
		t.Fatal("watch reported connected while it cannot be established")
	}

	api.SetError(kubetest.Watch, certRef, nil)
	waitConnected(t, m, certRef)
}

func TestWatchErrorEventIsCountedAndRecovered(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	api.SendEvent(certRef, watch.Event{Type: watch.Error, Object: &metav1.Status{
		Status: metav1.StatusFailure, Code: 410, Reason: metav1.StatusReasonExpired, Message: "too old resource version: 1 (2)",
	}})
	eventually(t, "watch error counted and watch re-established", func() bool {
		st := status(m, certRef)
		return st.WatchErrors == 1 && api.CallCount(kubetest.Watch, certRef) == 2 && st.WatchConnected
	})
	if api.CallCount(kubetest.List, certRef) != 2 {
		t.Fatal("expected a relist after the error event")
	}
	if !m.Secret(certRef).Present {
		t.Fatal("state lost after watch error")
	}
}

func TestWatchEstablishFailureRetriesWithBackoff(t *testing.T) {
	api := kubetest.New()
	api.SetError(kubetest.Watch, certRef, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, certRef.Name, errors.New("no watch permission")))
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)

	eventually(t, "repeated watch attempts", func() bool { return status(m, certRef).WatchErrors >= 3 })
	st := status(m, certRef)
	if st.WatchConnected {
		t.Fatal("watch must not be reported connected")
	}
	// Each failed watch leads to a fresh list, so state keeps being refreshed.
	if !m.Secret(certRef).Present || api.CallCount(kubetest.List, certRef) < 3 {
		t.Fatal("expected relists between watch attempts")
	}
}

func TestListFailureDuringInitialSync(t *testing.T) {
	api := kubetest.New()
	api.SetError(kubetest.List, certRef, errors.New("apiserver unavailable"))
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)

	// Initialization completes: the attempt was made, and failed.
	s := m.Secret(certRef)
	if s.Present || s.Synced {
		t.Fatalf("snapshot = %+v, want unsynced", s)
	}
	eventually(t, "sync errors counted", func() bool { return status(m, certRef).SyncErrors >= 1 })
	if !status(m, certRef).LastSuccessfulSync.IsZero() {
		t.Fatal("last successful sync set without a successful sync")
	}

	api.SetError(kubetest.List, certRef, nil)
	eventually(t, "recovered", func() bool { return m.Secret(certRef).Present })
	waitConnected(t, m, certRef)
}

func TestWaitSynced(t *testing.T) {
	api := kubetest.New()
	api.SetError(kubetest.List, certRef, errors.New("apiserver unavailable"))
	m := start(t, api, fastOptions(), certRef, authRef)

	// The first list failed: the state of certRef is not known yet.
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.WaitSynced(short, certRef); err == nil {
		t.Fatal("WaitSynced returned before the Secret could be read")
	}
	// An absent Secret is a known state.
	if err := m.WaitSynced(context.Background(), authRef); err != nil {
		t.Fatal(err)
	}

	api.SetError(kubetest.List, certRef, nil)
	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := m.WaitSynced(ctx, certRef); err != nil {
		t.Fatalf("WaitSynced after recovery: %v", err)
	}
	if err := m.WaitSynced(ctx, exposure.SecretRef{Namespace: "x", Name: "y"}); err == nil {
		t.Fatal("WaitSynced accepted an unmanaged reference")
	}
}

func TestPeriodicReconciliationCorrectsStaleState(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "V1"))
	opts := fastOptions()
	opts.ReconcileInterval = 20 * time.Millisecond
	m := start(t, api, opts, certRef)
	waitConnected(t, m, certRef)
	firstSync := status(m, certRef).LastSuccessfulSync

	// Changes that never reach the watch.
	rv := api.ApplySilently(certRef, data("tls.crt", "V2"))
	waitVersion(t, m, certRef, rv)
	if got := string(m.Secret(certRef).Data["tls.crt"]); got != "V2" {
		t.Fatalf("data = %q", got)
	}
	if api.CallCount(kubetest.Get, certRef) == 0 {
		t.Fatal("reconciliation did not use GET")
	}

	api.DeleteSilently(certRef)
	waitAbsent(t, m, certRef)

	if !status(m, certRef).LastSuccessfulSync.After(firstSync) {
		t.Fatal("reconciliation did not advance the last successful sync time")
	}
	// Drift means the watch missed events, so it is replaced after a relist.
	eventually(t, "watch replaced", func() bool { return api.CallCount(kubetest.Watch, certRef) >= 2 })
}

func TestReconciliationFailureKeepsWatch(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "V1"))
	api.SetError(kubetest.Get, certRef, errors.New("timeout"))
	opts := fastOptions()
	opts.ReconcileInterval = 10 * time.Millisecond
	m := start(t, api, opts, certRef)
	waitConnected(t, m, certRef)

	eventually(t, "sync errors counted", func() bool { return status(m, certRef).SyncErrors >= 2 })
	if n := api.CallCount(kubetest.Watch, certRef); n != 1 {
		t.Fatalf("a failed reconciliation must not drop a healthy watch, got %d watches", n)
	}
	if !m.Secret(certRef).Present {
		t.Fatal("state lost on reconciliation failure")
	}
}

func TestDuplicateReferencesShareOneWatcher(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	api.Apply(authRef, data("username", "u", "password", "p"))
	m := start(t, api, fastOptions(), certRef, authRef, certRef, certRef, authRef)
	waitConnected(t, m, certRef)
	waitConnected(t, m, authRef)

	if n := len(m.Statuses()); n != 2 {
		t.Fatalf("got %d state entries, want 2", n)
	}
	for _, ref := range []exposure.SecretRef{certRef, authRef} {
		if l, w := api.CallCount(kubetest.List, ref), api.CallCount(kubetest.Watch, ref); l != 1 || w != 1 {
			t.Fatalf("%s: %d lists and %d watches, want exactly one each", ref, l, w)
		}
	}
}

func TestMalformedObjectsNeverCrash(t *testing.T) {
	api := kubetest.New()
	rv := api.Apply(certRef, data("tls.crt", "CERT"))
	var logs lockedBuffer
	opts := fastOptions()
	opts.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := start(t, api, opts, certRef)
	waitConnected(t, m, certRef)

	leaky := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "other"},
		Data:       map[string][]byte{"k": []byte("LEAKED-VALUE")},
	}
	events := []watch.Event{
		{Type: watch.Added, Object: nil},
		{Type: watch.Modified, Object: (*corev1.Secret)(nil)},
		{Type: watch.Modified, Object: &corev1.ConfigMap{Data: map[string]string{"k": "LEAKED-VALUE"}}},
		{Type: watch.Modified, Object: leaky},
		{Type: watch.Deleted, Object: leaky},
		{Type: watch.Deleted, Object: nil},
		{Type: watch.Error, Object: leaky},
		{Type: watch.Error, Object: nil},
		{Type: watch.Error, Object: &metav1.Status{Message: `decode failed: {"data":{"k":"LEAKED-VALUE"}}`}},
		{Type: "BOGUS", Object: leaky},
		{Type: watch.Bookmark, Object: leaky},
	}
	for i, ev := range events {
		before := api.CallCount(kubetest.Watch, certRef)
		api.SendEvent(certRef, ev)
		if ev.Type == watch.Bookmark {
			continue
		}
		eventually(t, "resync after malformed event", func() bool {
			return api.CallCount(kubetest.Watch, certRef) > before && status(m, certRef).WatchConnected
		})
		if s := m.Secret(certRef); !s.Present || s.ResourceVersion != rv || string(s.Data["tls.crt"]) != "CERT" {
			t.Fatalf("event %d (%s) corrupted state: %+v", i, ev.Type, s)
		}
	}
	if got := status(m, certRef).WatchErrors; got != uint64(len(events)-1) {
		t.Fatalf("watch errors = %d, want %d", got, len(events)-1)
	}

	// A Secret without any data is present and simply has no keys.
	rv = api.Apply(certRef, nil)
	waitVersion(t, m, certRef, rv)
	if s := m.Secret(certRef); len(s.Data) != 0 {
		t.Fatalf("data = %v, want empty", s.Data)
	}

	if strings.Contains(logs.String(), "LEAKED-VALUE") {
		t.Fatalf("object data appeared in logs:\n%s", logs.String())
	}
}

func TestListWithUnexpectedObjectsKeepsState(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	api.SetListResult(certRef, &corev1.SecretList{Items: []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "other"}}}})
	api.CloseWatches(certRef)
	eventually(t, "sync error", func() bool { return status(m, certRef).SyncErrors >= 1 })
	if !m.Secret(certRef).Present {
		t.Fatal("an unexpected list result must not mark the Secret absent")
	}
	api.SetListResult(certRef, nil)
	waitConnected(t, m, certRef)
}

func TestNilResultsFromClient(t *testing.T) {
	m := start(t, nilClient{}, fastOptions(), certRef)
	eventually(t, "sync errors", func() bool { return status(m, certRef).SyncErrors >= 2 })
	if m.Secret(certRef).Synced {
		t.Fatal("a nil list must not count as a successful sync")
	}
}

type nilClient struct{}

func (nilClient) ListSecret(context.Context, exposure.SecretRef) (*corev1.SecretList, error) {
	return nil, nil
}

func (nilClient) WatchSecret(context.Context, exposure.SecretRef, string, time.Duration) (watch.Interface, error) {
	return nil, nil
}

func (nilClient) GetSecret(context.Context, exposure.SecretRef) (*corev1.Secret, error) {
	return nil, nil
}

func TestPanickingClientIsContained(t *testing.T) {
	var calls sync.Map
	client := panicClient{calls: &calls}
	m := start(t, client, fastOptions(), certRef)
	eventually(t, "repeated attempts after panics", func() bool { return status(m, certRef).WatchErrors >= 2 })
}

type panicClient struct{ calls *sync.Map }

func (panicClient) ListSecret(context.Context, exposure.SecretRef) (*corev1.SecretList, error) {
	panic("boom")
}

func (panicClient) WatchSecret(context.Context, exposure.SecretRef, string, time.Duration) (watch.Interface, error) {
	panic("boom")
}

func (panicClient) GetSecret(context.Context, exposure.SecretRef) (*corev1.Secret, error) {
	panic("boom")
}

func TestUnknownReferenceIsAbsent(t *testing.T) {
	m := start(t, kubetest.New(), fastOptions(), certRef)
	if s := m.Secret(exposure.SecretRef{Namespace: "x", Name: "y"}); s.Present || s.Synced {
		t.Fatalf("unknown reference reported as %+v", s)
	}
}

func TestSnapshotsAreIsolatedFromClientObjects(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := start(t, api, fastOptions(), certRef)
	first := m.Secret(certRef)
	rv := api.Apply(certRef, data("tls.crt", "NEW"))
	waitVersion(t, m, certRef, rv)
	if string(first.Data["tls.crt"]) != "CERT" {
		t.Fatal("an earlier snapshot changed after an update")
	}
}

func TestStopEndsAllWatchers(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "CERT"))
	m := resources.NewManager(api, []exposure.SecretRef{certRef, authRef}, fastOptions())
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	m.Start(ctx) // second Start is a no-op
	eventually(t, "connected", func() bool { return status(m, certRef).WatchConnected && status(m, authRef).WatchConnected })

	cancel()
	done := make(chan struct{})
	go func() { m.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchers did not stop")
	}
	if api.CallCount(kubetest.Watch, certRef) != 1 {
		t.Fatal("duplicate watch after second Start")
	}
	if status(m, certRef).WatchConnected {
		t.Fatal("watch still reported connected after stop")
	}
}

func TestNoReferences(t *testing.T) {
	m := resources.NewManager(kubetest.New(), nil, fastOptions())
	if !m.Initialized() {
		t.Fatal("a manager without references is initialized immediately")
	}
}

func TestConcurrentReadersDuringUpdates(t *testing.T) {
	api := kubetest.New()
	api.Apply(certRef, data("tls.crt", "0"))
	m := start(t, api, fastOptions(), certRef)
	waitConnected(t, m, certRef)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				s := m.Secret(certRef)
				for k, v := range s.Data {
					_, _ = k, len(v)
				}
				_ = m.Statuses()
			}
		}()
	}
	for i := range 50 {
		if i%10 == 9 {
			api.Delete(certRef)
			continue
		}
		api.Apply(certRef, data("tls.crt", strings.Repeat("x", i)))
	}
	rv := api.Apply(certRef, data("tls.crt", "final"))
	waitVersion(t, m, certRef, rv)
	cancel()
	wg.Wait()
}

// lockedBuffer is a bytes.Buffer safe for concurrent log writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
