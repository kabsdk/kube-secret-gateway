package resources

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestDescribeErrorRedactsEmbeddedObjects(t *testing.T) {
	body := `{"kind":"","data":{"password":"c2VjcmV0"}}`
	cases := []error{
		runtime.NewMissingKindErr(body),
		fmt.Errorf("unable to decode watch event: %w", runtime.NewMissingKindErr(body)),
		apierrors.NewInternalError(errors.New("decode: " + body)),
	}
	for _, err := range cases {
		got := describeError(err)
		if strings.Contains(got, "c2VjcmV0") || strings.Contains(got, "password") {
			t.Errorf("describeError leaked object content: %q", got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("describeError(%v) = %q, want redaction marker", err, got)
		}
	}
}

func TestDescribeErrorKeepsStatusDetails(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "my-cert", errors.New("not allowed"))
	got := describeError(err)
	if !strings.HasPrefix(got, "403 Forbidden: ") || !strings.Contains(got, `secrets "my-cert" is forbidden`) {
		t.Fatalf("describeError = %q", got)
	}
	if got := describeError(errors.New(strings.Repeat("x", 2000))); len(got) > 600 {
		t.Fatalf("long errors must be truncated, got %d bytes", len(got))
	}
}

func TestDescribeWatchErrorNeverFormatsObjects(t *testing.T) {
	got := describeWatchError(&metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"k": "SENSITIVE"}}})
	if strings.Contains(got, "SENSITIVE") {
		t.Fatalf("leaked: %q", got)
	}
	if got := describeWatchError(&metav1.Status{Code: 410, Reason: metav1.StatusReasonExpired, Message: "too old"}); got != "410 Expired: too old" {
		t.Fatalf("describeWatchError = %q", got)
	}
}

func TestBackoffBounds(t *testing.T) {
	b := backoff{initial: 100 * time.Millisecond, max: 800 * time.Millisecond}
	ceilings := []time.Duration{100, 200, 400, 800, 800, 800}
	for i, ceiling := range ceilings {
		ceiling *= time.Millisecond
		d := b.next()
		if d < ceiling/2 || d > ceiling {
			t.Fatalf("attempt %d: delay %v outside [%v, %v]", i, d, ceiling/2, ceiling)
		}
	}
	b.reset()
	if d := b.next(); d > 100*time.Millisecond {
		t.Fatalf("delay after reset = %v", d)
	}
}

func TestJitterBounds(t *testing.T) {
	for range 1000 {
		d := jitter(time.Minute)
		if d < 54*time.Second || d > 66*time.Second {
			t.Fatalf("jitter(1m) = %v", d)
		}
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.ReconcileInterval != 5*time.Minute || o.RequestTimeout <= 0 || o.WatchTimeout <= 0 ||
		o.InitialBackoff <= 0 || o.MaxBackoff < o.InitialBackoff || o.StableWatchDuration <= 0 || o.Logger == nil {
		t.Fatalf("defaults = %+v", o)
	}
}
