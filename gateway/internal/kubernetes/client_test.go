package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"kube-secret-gateway/internal/exposure"
)

var ref = exposure.SecretRef{Namespace: "certificates", Name: "my-cert"}

func newFake() *fake.Clientset {
	return fake.NewClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "certificates", Name: "my-cert"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "certificates", Name: "unrelated"}},
	)
}

func TestListIsRestrictedToExactName(t *testing.T) {
	cs := newFake()
	if _, err := NewSecretClient(cs).ListSecret(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	actions := cs.Actions()
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	list, ok := actions[0].(k8stesting.ListAction)
	if !ok || list.GetResource().Resource != "secrets" {
		t.Fatalf("unexpected action %#v", actions[0])
	}
	if ns := list.GetNamespace(); ns != "certificates" {
		t.Fatalf("namespace = %q", ns)
	}
	if sel := list.GetListRestrictions().Fields.String(); sel != "metadata.name=my-cert" {
		t.Fatalf("field selector = %q, want metadata.name=my-cert", sel)
	}
}

func TestWatchIsRestrictedToExactName(t *testing.T) {
	cs := newFake()
	w, err := NewSecretClient(cs).WatchSecret(context.Background(), ref, "42", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	w.Stop()
	actions := cs.Actions()
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	wa, ok := actions[0].(k8stesting.WatchAction)
	if !ok || wa.GetResource().Resource != "secrets" {
		t.Fatalf("unexpected action %#v", actions[0])
	}
	if ns := wa.GetNamespace(); ns != "certificates" {
		t.Fatalf("namespace = %q", ns)
	}
	r := wa.GetWatchRestrictions()
	if sel := r.Fields.String(); sel != "metadata.name=my-cert" {
		t.Fatalf("field selector = %q, want metadata.name=my-cert", sel)
	}
	if r.ResourceVersion != "42" {
		t.Fatalf("resourceVersion = %q", r.ResourceVersion)
	}
}

func TestGetUsesExactName(t *testing.T) {
	cs := newFake()
	s, err := NewSecretClient(cs).GetSecret(context.Background(), ref)
	if err != nil || s.Name != "my-cert" {
		t.Fatalf("GetSecret = %v, %v", s, err)
	}
	get, ok := cs.Actions()[0].(k8stesting.GetAction)
	if !ok || get.GetName() != "my-cert" || get.GetNamespace() != "certificates" {
		t.Fatalf("unexpected action %#v", cs.Actions()[0])
	}
}

func TestIncompleteReferencesNeverReachTheAPI(t *testing.T) {
	cs := newFake()
	c := NewSecretClient(cs)
	ctx := context.Background()
	for _, bad := range []exposure.SecretRef{{Name: "my-cert"}, {Namespace: "certificates"}, {}} {
		if _, err := c.ListSecret(ctx, bad); !errors.Is(err, errIncompleteRef) {
			t.Errorf("ListSecret(%v) err = %v", bad, err)
		}
		if _, err := c.WatchSecret(ctx, bad, "", time.Minute); !errors.Is(err, errIncompleteRef) {
			t.Errorf("WatchSecret(%v) err = %v", bad, err)
		}
		if _, err := c.GetSecret(ctx, bad); !errors.Is(err, errIncompleteRef) {
			t.Errorf("GetSecret(%v) err = %v", bad, err)
		}
	}
	if n := len(cs.Actions()); n != 0 {
		t.Fatalf("%d requests issued for incomplete references", n)
	}
}
