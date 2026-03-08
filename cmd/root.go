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
	namespace    string
	kubeconfig   string
	outputFormat string
)

// rootCmd is the base command for kubectl-rbacmap.
var rootCmd = &cobra.Command{
	Use:   "kubectl-rbacmap",
	Short: "Map RBAC permissions for Kubernetes subjects",
	Long: `kubectl-rbacmap finds all permissions associated with Kubernetes subjects
(ServiceAccounts, Users, Groups) by inspecting Roles, ClusterRoles,
RoleBindings, and ClusterRoleBindings.

Usage as a kubectl plugin:
  kubectl rbacmap --subjects sa:my-service-account -n my-namespace

Subject format:
  sa:<name>              ServiceAccount (uses -n namespace or "default")
  serviceaccount:<name>  ServiceAccount (same as sa)
  user:<name>            User
  group:<name>           Group`,
	SilenceUsage: true,
	RunE:         run,
}

func init() {
	rootCmd.Flags().StringSliceVar(&subjects, "subjects", nil,
		"Comma-separated list of subjects in kind:name format (e.g. sa:mysa,user:admin@example.com)")
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "",
		"Namespace for ServiceAccount subjects (defaults to 'default')")
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "",
		"Path to kubeconfig file (defaults to KUBECONFIG env or ~/.kube/config)")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "table",
		"Output format: table (default), markdown, csv")

	_ = rootCmd.MarkFlagRequired("subjects")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
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

	client, err := kube.NewClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	ctx := context.Background()

	results, err := rbac.ResolvePermissions(ctx, client, parsed, namespace)
	if err != nil {
		return fmt.Errorf("resolving permissions: %w", err)
	}

	rbacfmt.PrintSubjectPermissions(os.Stdout, results, outputFormat)

	return nil
}
