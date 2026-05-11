package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	rbacfmt "github.com/hrishis/kubectl-rbacmap/pkg/fmt"
	"github.com/hrishis/kubectl-rbacmap/pkg/kube"
	"github.com/hrishis/kubectl-rbacmap/pkg/rbac"
)

var (
	subjects     []string
	resource     string
	verbs        []string
	namespace    string
	kubeconfig   string
	outputFormat string
)

// rootCmd is the base command for kubectl-rbacmap.
var rootCmd = &cobra.Command{
	Use:   "kubectl-rbac-map",
	Short: "Map RBAC permissions for Kubernetes subjects",
	Long: `kubectl-rbac-map finds all permissions associated with Kubernetes subjects
(ServiceAccounts, Users, Groups) by inspecting Roles, ClusterRoles,
RoleBindings, and ClusterRoleBindings.

Usage as a kubectl plugin:
  kubectl rbac-map --subjects sa:my-service-account -n my-namespace
  kubectl rbac-map --resource pods
  kubectl rbac-map --resource deployments.apps --verbs get,list

Subject format:
  sa:<name>              ServiceAccount (uses -n namespace or "default")
  serviceaccount:<name>  ServiceAccount (same as sa)
  user:<name>            User
  group:<name>           Group

Resource format:
  pods                   Core API resource
  deployments.apps       Resource with API group (resource.group)
  apps/deployments       Resource with API group (group/resource)`,
	SilenceUsage: true,
	RunE:         run,
}

func init() {
	rootCmd.Flags().StringSliceVar(&subjects, "subjects", nil,
		"Comma-separated list of subjects in kind:name format (e.g. sa:mysa,user:admin@example.com)")
	rootCmd.Flags().StringVar(&resource, "resource", "",
		"Resource to look up subjects for (e.g. pods, deployments.apps, apps/deployments)")
	rootCmd.Flags().StringSliceVar(&verbs, "verbs", nil,
		"Filter by verbs when using --resource (e.g. get,list,watch)")
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "",
		"Namespace scope: for ServiceAccount subjects or to limit RoleBinding lookup")
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "",
		"Path to kubeconfig file (defaults to KUBECONFIG env or ~/.kube/config)")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "table",
		"Output format: table (default), markdown, csv")

	rootCmd.MarkFlagsMutuallyExclusive("subjects", "resource")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if resource == "" && len(subjects) == 0 {
		return fmt.Errorf("either --subjects or --resource is required")
	}

	client, err := kube.NewClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	ctx := context.Background()

	if resource != "" {
		return runResourceLookup(ctx, client)
	}
	return runSubjectLookup(ctx, client)
}

func runSubjectLookup(ctx context.Context, client *kube.Client) error {
	// Normalize subjects: the flag parser splits on comma, but users may
	// include spaces. Flatten and re-split to handle "sa:a, sa:b" style input.
	var normalized []string
	for _, s := range subjects {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				normalized = append(normalized, part)
			}
		}
	}

	parsed, err := rbac.ParseSubjects(normalized, namespace)
	if err != nil {
		return fmt.Errorf("parsing subjects: %w", err)
	}

	// Try to expand cloud provider identities (e.g. AWS IAM ARNs) to Kubernetes subjects
	expanded, err := rbac.ExpandSubjects(ctx, client, parsed)
	if err != nil {
		// Not all clusters have mapping ConfigMaps like aws-auth; ignore silently.
	}

	results, err := rbac.ResolvePermissions(ctx, client, expanded, namespace)
	if err != nil {
		return fmt.Errorf("resolving permissions: %w", err)
	}

	rbacfmt.PrintSubjectPermissions(os.Stdout, results, outputFormat)
	return nil
}

func runResourceLookup(ctx context.Context, client *kube.Client) error {
	// Normalize verbs (same comma-splitting as subjects).
	var normalizedVerbs []string
	for _, v := range verbs {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				normalizedVerbs = append(normalizedVerbs, part)
			}
		}
	}

	accesses, err := rbac.FindSubjectsForResource(ctx, client, resource, normalizedVerbs, namespace)
	if err != nil {
		return fmt.Errorf("finding subjects for resource: %w", err)
	}

	rbacfmt.PrintResourceAccess(os.Stdout, resource, accesses, outputFormat)
	return nil
}
