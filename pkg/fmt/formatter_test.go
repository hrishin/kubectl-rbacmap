package fmt

import (
	"testing"

	"github.com/hrishis/kubectl-rbacmap/pkg/rbac"
)

func TestMergeActions(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		new      string
		expected string
	}{
		{
			name:     "empty strings",
			existing: "",
			new:      "",
			expected: "",
		},
		{
			name:     "merge disjoint",
			existing: "get,list",
			new:      "watch,create",
			expected: "get,list,watch,create",
		},
		{
			name:     "merge duplicates",
			existing: "get,list",
			new:      "list,watch",
			expected: "get,list,watch",
		},
		{
			name:     "whitespace handling",
			existing: " get , list ",
			new:      " watch , get",
			expected: "get,list,watch",
		},
		{
			name:     "asterisk wildcard",
			existing: "*",
			new:      "get,list",
			expected: "*,get,list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeActions(tt.existing, tt.new)
			if result != tt.expected {
				t.Errorf("mergeActions(%q, %q) = %q; want %q", tt.existing, tt.new, result, tt.expected)
			}
		})
	}
}

func TestGroupByResource(t *testing.T) {
	perms := []rbac.Permission{
		{
			Resource: "pods",
			Actions:  []string{"get", "list"},
			RoleType: "Role",
			RoleName: "pod-reader",
			Source: rbac.BindingSource{
				BindingType: "RoleBinding",
				BindingName: "pod-reader-binding",
				Namespace:   "default",
			},
		},
		{
			Resource: "pods",
			Actions:  []string{"watch"},
			RoleType: "Role",
			RoleName: "pod-reader",
			Source: rbac.BindingSource{
				BindingType: "RoleBinding",
				BindingName: "pod-reader-binding",
				Namespace:   "default",
			},
		},
		{
			Resource: "secrets",
			Actions:  []string{"get"},
			RoleType: "ClusterRole",
			RoleName: "secret-reader",
			Source: rbac.BindingSource{
				BindingType: "ClusterRoleBinding",
				BindingName: "secret-reader",
			},
		},
	}

	grouped := groupByResource(perms)

	if len(grouped) != 2 {
		t.Fatalf("expected 2 grouped resources, got %d", len(grouped))
	}

	// Verify pods got merged
	if grouped[0].Resource != "pods" {
		t.Errorf("expected first group resource 'pods', got %q", grouped[0].Resource)
	}
	if grouped[0].Actions != "get,list,watch" {
		t.Errorf("expected merged actions 'get,list,watch', got %q", grouped[0].Actions)
	}
	expectedPodBinding := "RoleBinding: pod-reader: NS:<default>"
	if grouped[0].BindingRef != expectedPodBinding {
		t.Errorf("expected binding ref %q, got %q", expectedPodBinding, grouped[0].BindingRef)
	}

	// Verify secrets is standalone
	if grouped[1].Resource != "secrets" {
		t.Errorf("expected second group resource 'secrets', got %q", grouped[1].Resource)
	}
	expectedSecretBinding := "ClusterRoleBinding: secret-reader"
	if grouped[1].BindingRef != expectedSecretBinding {
		t.Errorf("expected binding ref %q, got %q", expectedSecretBinding, grouped[1].BindingRef)
	}
}

func TestSubjectKindLabel(t *testing.T) {
	tests := []struct {
		kind     rbac.SubjectKind
		expected string
	}{
		{rbac.KindServiceAccount, "Service Account"},
		{rbac.KindUser, "User"},
		{rbac.KindGroup, "Group"},
		{rbac.SubjectKind("Unknown"), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			result := subjectKindLabel(rbac.Subject{Kind: tt.kind})
			if result != tt.expected {
				t.Errorf("subjectKindLabel(%s) = %q; want %q", tt.kind, result, tt.expected)
			}
		})
	}
}
