package kube

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps a Kubernetes clientset and provides RBAC query methods.
type Client struct {
	clientset *kubernetes.Clientset
}

// NewClient creates a new Kubernetes client using the default kubeconfig
// resolution order (--kubeconfig flag, KUBECONFIG env, ~/.kube/config).
func NewClient(kubeconfig string) (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}

	configOverrides := &clientcmd.ConfigOverrides{}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &Client{clientset: cs}, nil
}

// ListRoles returns all Roles in the given namespace (empty string means all namespaces).
func (c *Client) ListRoles(ctx context.Context, namespace string) ([]rbacv1.Role, error) {
	list, err := c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	return list.Items, nil
}

// ListClusterRoles returns all ClusterRoles.
func (c *Client) ListClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error) {
	list, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}
	return list.Items, nil
}

// ListRoleBindings returns all RoleBindings in the given namespace (empty string means all namespaces).
func (c *Client) ListRoleBindings(ctx context.Context, namespace string) ([]rbacv1.RoleBinding, error) {
	list, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list role bindings: %w", err)
	}
	return list.Items, nil
}

// ListClusterRoleBindings returns all ClusterRoleBindings.
func (c *Client) ListClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	list, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}
	return list.Items, nil
}
