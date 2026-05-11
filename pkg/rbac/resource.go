package rbac

import (
	"context"
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hrishis/kubectl-rbacmap/pkg/kube"
)

// ResourceAccess captures which subject can access a resource and via what role/binding.
type ResourceAccess struct {
	Subject  Subject
	Actions  []string
	RoleType string // "Role" or "ClusterRole"
	RoleName string
	Source   BindingSource
}

// FindSubjectsForResource finds all subjects that have access to the given resource.
// resource supports formats: "pods", "deployments.apps", or "apps/deployments".
// filterVerbs narrows results to subjects with at least one matching verb (empty = any verb).
// namespace controls which RoleBindings to inspect (empty = all namespaces).
func FindSubjectsForResource(ctx context.Context, client *kube.Client, resource string, filterVerbs []string, namespace string) ([]ResourceAccess, error) {
	roles, err := client.ListRoles(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	clusterRoles, err := client.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}

	roleBindings, err := client.ListRoleBindings(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("listing role bindings: %w", err)
	}

	clusterRoleBindings, err := client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cluster role bindings: %w", err)
	}

	targetGroup, targetResource := parseResourceInput(resource)

	// Build maps: key → matched verbs for roles that grant access to the resource.
	roleMatches := make(map[string][]string)        // "namespace/name" -> matched verbs
	clusterRoleMatches := make(map[string][]string) // "name" -> matched verbs

	for _, r := range roles {
		matched := matchedVerbs(r.Rules, targetGroup, targetResource, filterVerbs)
		if len(matched) > 0 {
			roleMatches[r.Namespace+"/"+r.Name] = matched
		}
	}

	for _, cr := range clusterRoles {
		matched := matchedVerbs(cr.Rules, targetGroup, targetResource, filterVerbs)
		if len(matched) > 0 {
			clusterRoleMatches[cr.Name] = matched
		}
	}

	var accesses []ResourceAccess

	for _, rb := range roleBindings {
		var verbs []string
		switch rb.RoleRef.Kind {
		case "Role":
			verbs = roleMatches[rb.Namespace+"/"+rb.RoleRef.Name]
		case "ClusterRole":
			verbs = clusterRoleMatches[rb.RoleRef.Name]
		}
		if len(verbs) == 0 {
			continue
		}

		source := BindingSource{
			BindingType: "RoleBinding",
			BindingName: rb.Name,
			Namespace:   rb.Namespace,
		}
		for _, s := range rb.Subjects {
			accesses = append(accesses, ResourceAccess{
				Subject:  subjectFromRBACSubject(s, rb.Namespace),
				Actions:  verbs,
				RoleType: rb.RoleRef.Kind,
				RoleName: rb.RoleRef.Name,
				Source:   source,
			})
		}
	}

	for _, crb := range clusterRoleBindings {
		verbs := clusterRoleMatches[crb.RoleRef.Name]
		if len(verbs) == 0 {
			continue
		}

		source := BindingSource{
			BindingType: "ClusterRoleBinding",
			BindingName: crb.Name,
		}
		for _, s := range crb.Subjects {
			accesses = append(accesses, ResourceAccess{
				Subject:  subjectFromRBACSubject(s, ""),
				Actions:  verbs,
				RoleType: crb.RoleRef.Kind,
				RoleName: crb.RoleRef.Name,
				Source:   source,
			})
		}
	}

	return accesses, nil
}

// parseResourceInput splits a resource string into (apiGroup, resourceName).
// Supported formats: "pods", "apps/deployments", "deployments.apps".
func parseResourceInput(resource string) (group, res string) {
	if strings.Contains(resource, "/") {
		parts := strings.SplitN(resource, "/", 2)
		return parts[0], parts[1]
	}
	if idx := strings.Index(resource, "."); idx > 0 {
		// "deployments.apps" or "ingresses.networking.k8s.io" → split on first dot
		return resource[idx+1:], resource[:idx]
	}
	return "", resource
}

// matchedVerbs returns the verbs from rules that apply to the given resource.
// If filterVerbs is non-empty, only those verbs (or the intersection) are returned.
func matchedVerbs(rules []rbacv1.PolicyRule, targetGroup, targetResource string, filterVerbs []string) []string {
	seen := make(map[string]bool)
	var ordered []string

	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			ordered = append(ordered, v)
		}
	}

	filterSet := make(map[string]bool)
	for _, fv := range filterVerbs {
		filterSet[fv] = true
	}

	for _, rule := range rules {
		if !ruleMatchesResource(rule, targetGroup, targetResource) {
			continue
		}

		hasWildcard := slices.Contains(rule.Verbs, "*")

		switch {
		case len(filterVerbs) == 0:
			for _, v := range rule.Verbs {
				add(v)
			}
		case hasWildcard:
			for _, fv := range filterVerbs {
				add(fv)
			}
		default:
			for _, v := range rule.Verbs {
				if filterSet[v] {
					add(v)
				}
			}
		}
	}

	return ordered
}

// ruleMatchesResource checks whether a PolicyRule covers the given resource and API group.
func ruleMatchesResource(rule rbacv1.PolicyRule, targetGroup, targetResource string) bool {
	resourceMatch := false
	for _, r := range rule.Resources {
		if r == "*" || r == targetResource {
			resourceMatch = true
			break
		}
	}
	if !resourceMatch {
		return false
	}

	for _, g := range rule.APIGroups {
		if g == "*" || g == targetGroup {
			return true
		}
	}
	return false
}

// subjectFromRBACSubject converts an rbacv1.Subject to our Subject type.
func subjectFromRBACSubject(s rbacv1.Subject, defaultNamespace string) Subject {
	switch s.Kind {
	case "ServiceAccount":
		ns := s.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		return Subject{Kind: KindServiceAccount, Name: s.Name, Namespace: ns}
	case "User":
		return Subject{Kind: KindUser, Name: s.Name}
	case "Group":
		return Subject{Kind: KindGroup, Name: s.Name}
	default:
		return Subject{Kind: SubjectKind(s.Kind), Name: s.Name}
	}
}
