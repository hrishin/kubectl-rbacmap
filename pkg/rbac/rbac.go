package rbac

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hrishis/kubectl-rbacmap/pkg/kube"
)

// SubjectKind represents the type of Kubernetes RBAC subject.
type SubjectKind string

const (
	KindServiceAccount SubjectKind = "ServiceAccount"
	KindUser           SubjectKind = "User"
	KindGroup          SubjectKind = "Group"
)

// Subject represents a parsed RBAC subject from the CLI input.
type Subject struct {
	Kind      SubjectKind
	Name      string
	Namespace string // only relevant for ServiceAccounts
}

// BindingSource captures where a permission came from (which binding + role).
type BindingSource struct {
	BindingType string // "RoleBinding" or "ClusterRoleBinding"
	BindingName string
	Namespace   string // namespace of the RoleBinding (empty for ClusterRoleBinding)
}

// Permission represents a single resource permission granted to a subject.
type Permission struct {
	Resource string
	Actions  []string
	RoleType string // "Role" or "ClusterRole"
	RoleName string
	Source   BindingSource
}

// SubjectPermissions holds all resolved permissions for a subject.
type SubjectPermissions struct {
	Subject     Subject
	Permissions []Permission
}

// ParseSubjects parses a list of subject strings in the format "kind:name".
// Supported kinds (case-insensitive): sa, serviceaccount, user, group.
// For ServiceAccounts without an explicit namespace, defaultNamespace is used.
func ParseSubjects(subjects []string, defaultNamespace string) ([]Subject, error) {
	var parsed []Subject

	for _, s := range subjects {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return nil, fmt.Errorf("invalid subject format %q: expected kind:name", s)
		}

		kind := strings.ToLower(parts[0])
		name := parts[1]

		switch kind {
		case "sa", "serviceaccount":
			ns := defaultNamespace
			if ns == "" {
				ns = "default"
			}
			parsed = append(parsed, Subject{
				Kind:      KindServiceAccount,
				Name:      name,
				Namespace: ns,
			})
		case "user":
			parsed = append(parsed, Subject{
				Kind: KindUser,
				Name: name,
			})
		case "group":
			parsed = append(parsed, Subject{
				Kind: KindGroup,
				Name: name,
			})
		default:
			return nil, fmt.Errorf("unknown subject kind %q: supported kinds are sa, serviceaccount, user, group", kind)
		}
	}

	if len(parsed) == 0 {
		return nil, fmt.Errorf("no valid subjects provided")
	}

	return parsed, nil
}

// ResolvePermissions queries the Kubernetes API for all RBAC bindings and roles,
// then resolves which permissions apply to each subject.
func ResolvePermissions(ctx context.Context, client *kube.Client, subjects []Subject, namespace string) ([]SubjectPermissions, error) {
	// Fetch all bindings
	roleBindings, err := client.ListRoleBindings(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("listing role bindings: %w", err)
	}

	clusterRoleBindings, err := client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cluster role bindings: %w", err)
	}

	// Fetch all roles
	roles, err := client.ListRoles(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	clusterRoles, err := client.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}

	// Build lookup maps for roles
	roleMap := make(map[string]rbacv1.Role)
	for _, r := range roles {
		key := r.Namespace + "/" + r.Name
		roleMap[key] = r
	}

	clusterRoleMap := make(map[string]rbacv1.ClusterRole)
	for _, cr := range clusterRoles {
		clusterRoleMap[cr.Name] = cr
	}

	var results []SubjectPermissions

	for _, subj := range subjects {
		sp := SubjectPermissions{Subject: subj}

		// Check RoleBindings
		for _, rb := range roleBindings {
			if !bindingMatchesSubject(rb.Subjects, subj) {
				continue
			}

			rules := resolveRoleRef(rb.RoleRef, roleMap, clusterRoleMap, rb.Namespace)
			source := BindingSource{
				BindingType: "RoleBinding",
				BindingName: rb.Name,
				Namespace:   rb.Namespace,
			}

			perms := rulesToPermissions(rules, rb.RoleRef, source)
			sp.Permissions = append(sp.Permissions, perms...)
		}

		// Check ClusterRoleBindings
		for _, crb := range clusterRoleBindings {
			if !bindingMatchesSubject(crb.Subjects, subj) {
				continue
			}

			rules := resolveClusterRoleRef(crb.RoleRef, clusterRoleMap)
			source := BindingSource{
				BindingType: "ClusterRoleBinding",
				BindingName: crb.Name,
			}

			perms := rulesToPermissions(rules, crb.RoleRef, source)
			sp.Permissions = append(sp.Permissions, perms...)
		}

		results = append(results, sp)
	}

	return results, nil
}

// bindingMatchesSubject checks whether any subject in the binding matches our target subject.
func bindingMatchesSubject(bindingSubjects []rbacv1.Subject, target Subject) bool {
	for _, bs := range bindingSubjects {
		switch target.Kind {
		case KindServiceAccount:
			if bs.Kind == "ServiceAccount" && bs.Name == target.Name && bs.Namespace == target.Namespace {
				return true
			}
		case KindUser:
			if bs.Kind == "User" && bs.Name == target.Name {
				return true
			}
		case KindGroup:
			if bs.Kind == "Group" && bs.Name == target.Name {
				return true
			}
		}
	}
	return false
}

// resolveRoleRef looks up the policy rules for a RoleRef from a RoleBinding.
func resolveRoleRef(ref rbacv1.RoleRef, roleMap map[string]rbacv1.Role, clusterRoleMap map[string]rbacv1.ClusterRole, namespace string) []rbacv1.PolicyRule {
	switch ref.Kind {
	case "Role":
		key := namespace + "/" + ref.Name
		if role, ok := roleMap[key]; ok {
			return role.Rules
		}
	case "ClusterRole":
		if cr, ok := clusterRoleMap[ref.Name]; ok {
			return cr.Rules
		}
	}
	return nil
}

// resolveClusterRoleRef looks up the policy rules for a RoleRef from a ClusterRoleBinding.
func resolveClusterRoleRef(ref rbacv1.RoleRef, clusterRoleMap map[string]rbacv1.ClusterRole) []rbacv1.PolicyRule {
	if ref.Kind == "ClusterRole" {
		if cr, ok := clusterRoleMap[ref.Name]; ok {
			return cr.Rules
		}
	}
	return nil
}

// rulesToPermissions converts PolicyRules into our Permission model.
func rulesToPermissions(rules []rbacv1.PolicyRule, roleRef rbacv1.RoleRef, source BindingSource) []Permission {
	var perms []Permission

	for _, rule := range rules {
		resources := rule.Resources
		if len(resources) == 0 {
			resources = []string{"*"}
		}

		verbs := rule.Verbs
		if len(verbs) == 0 {
			verbs = []string{"*"}
		}

		for _, res := range resources {
			// Prepend API group if non-empty and non-core
			for _, apiGroup := range rule.APIGroups {
				displayResource := res
				if apiGroup != "" {
					displayResource = apiGroup + "/" + res
				}

				perms = append(perms, Permission{
					Resource: displayResource,
					Actions:  verbs,
					RoleType: roleRef.Kind,
					RoleName: roleRef.Name,
					Source:   source,
				})
			}

			// If no API groups specified, still add the resource
			if len(rule.APIGroups) == 0 {
				perms = append(perms, Permission{
					Resource: res,
					Actions:  verbs,
					RoleType: roleRef.Kind,
					RoleName: roleRef.Name,
					Source:   source,
				})
			}
		}
	}

	return perms
}
