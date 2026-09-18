// Package kubernetes implements exact-name Secret access with the official
// Kubernetes client.
//
// Every list and watch carries the field selector metadata.name=<name> within
// an explicit namespace. This keeps requests compatible with RBAC rules that
// grant get, list and watch only for specific resourceNames, and it means the
// gateway never asks for Secrets it was not configured to serve.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"kube-secret-gateway/internal/exposure"
)

// errIncompleteRef guards against a namespace-wide or cluster-wide request:
// with an empty namespace, client-go lists Secrets across all namespaces.
var errIncompleteRef = errors.New("refusing Secret request without both namespace and name")

// SecretClient performs exact-name Secret requests.
type SecretClient struct {
	cs clientset.Interface
}

// NewSecretClient wraps a Kubernetes clientset.
func NewSecretClient(cs clientset.Interface) *SecretClient {
	return &SecretClient{cs: cs}
}

// ListSecret lists the single Secret named ref.Name in ref.Namespace.
func (c *SecretClient) ListSecret(ctx context.Context, ref exposure.SecretRef) (*corev1.SecretList, error) {
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	return c.cs.CoreV1().Secrets(ref.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: nameSelector(ref.Name),
	})
}

// WatchSecret watches the single Secret named ref.Name in ref.Namespace,
// starting after resourceVersion. The server closes the watch after timeout.
func (c *SecretClient) WatchSecret(ctx context.Context, ref exposure.SecretRef, resourceVersion string, timeout time.Duration) (watch.Interface, error) {
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	timeoutSeconds := int64(timeout / time.Second)
	return c.cs.CoreV1().Secrets(ref.Namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector:       nameSelector(ref.Name),
		ResourceVersion:     resourceVersion,
		AllowWatchBookmarks: true,
		TimeoutSeconds:      &timeoutSeconds,
	})
}

// GetSecret fetches the Secret named ref.Name in ref.Namespace.
func (c *SecretClient) GetSecret(ctx context.Context, ref exposure.SecretRef) (*corev1.Secret, error) {
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	return c.cs.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
}

func checkRef(ref exposure.SecretRef) error {
	if ref.Namespace == "" || ref.Name == "" {
		return errIncompleteRef
	}
	return nil
}

func nameSelector(name string) string {
	return fields.OneTermEqualSelector("metadata.name", name).String()
}

// RESTConfig returns the API client configuration. Inside a cluster it uses
// the pod's service account; kubeconfig (or $KUBECONFIG, or ~/.kube/config)
// is for running outside a cluster during development. The namespace of the
// selected kubeconfig context is deliberately never used.
func RESTConfig(kubeconfig, userAgent string) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes client configuration: %w", err)
	}
	cfg.UserAgent = userAgent
	// One list and one watch per Secret at startup; allow a modest burst so
	// that startup with a few dozen Secrets is not throttled client-side.
	cfg.QPS = 20
	cfg.Burst = 50
	return cfg, nil
}

// NewClientset creates a Kubernetes clientset from cfg.
func NewClientset(cfg *rest.Config) (clientset.Interface, error) {
	cs, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return cs, nil
}
