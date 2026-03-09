package rbac

import (
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestParseSubjects(t *testing.T) {
	tests := []struct {
		name          string
		subjects      []string
		defaultNs     string
		expected      []Subject
		expectError   bool
	}{
		{
			name:      "valid service account with default ns",
			subjects:  []string{"sa:mysa"},
			defaultNs: "test-ns",
			expected: []Subject{
				{Kind: KindServiceAccount, Name: "mysa", Namespace: "test-ns"},
			},
		},
		{
			name:      "valid service account missing ns uses default",
			subjects:  []string{"serviceaccount:mysa"},
			defaultNs: "",
			expected: []Subject{
				{Kind: KindServiceAccount, Name: "mysa", Namespace: "default"},
			},
		},
		{
			name:      "valid user and group",
			subjects:  []string{"user:admin@example.com", "group:developers"},
			expected: []Subject{
				{Kind: KindUser, Name: "admin@example.com"},
				{Kind: KindGroup, Name: "developers"},
			},
		},
		{
			name:        "invalid format missing colon",
			subjects:    []string{"invalid-subject"},
			expectError: true,
		},
		{
			name:        "unknown kind",
			subjects:    []string{"unknown:name"},
			expectError: true,
		},
		{
			name:        "empty subjects",
			subjects:    []string{"  ", ""},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSubjects(tt.subjects, tt.defaultNs)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBindingMatchesSubject(t *testing.T) {
	bindingSubjects := []rbacv1.Subject{
		{Kind: "ServiceAccount", Name: "default-sa", Namespace: "default"},
		{Kind: "User", Name: "admin"},
		{Kind: "Group", Name: "system:masters"},
	}

	tests := []struct {
		name     string
		target   Subject
		expected bool
	}{
		{
			name:     "matching service account",
			target:   Subject{Kind: KindServiceAccount, Name: "default-sa", Namespace: "default"},
			expected: true,
		},
		{
			name:     "mismatching service account namespace",
			target:   Subject{Kind: KindServiceAccount, Name: "default-sa", Namespace: "kube-system"},
			expected: false,
		},
		{
			name:     "matching user",
			target:   Subject{Kind: KindUser, Name: "admin"},
			expected: true,
		},
		{
			name:     "matching group",
			target:   Subject{Kind: KindGroup, Name: "system:masters"},
			expected: true,
		},
		{
			name:     "unknown user",
			target:   Subject{Kind: KindUser, Name: "unknown"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bindingMatchesSubject(bindingSubjects, tt.target)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRulesToPermissions(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "services"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"*"},
		},
	}

	roleRef := rbacv1.RoleRef{Kind: "Role", Name: "test-role"}
	source := BindingSource{BindingType: "RoleBinding", BindingName: "test-binding", Namespace: "default"}

	perms := rulesToPermissions(rules, roleRef, source)

	if len(perms) != 3 {
		t.Fatalf("expected 3 permissions, got %d", len(perms))
	}

	// Verify core group resources (no API group prefix)
	if perms[0].Resource != "pods" || !reflect.DeepEqual(perms[0].Actions, []string{"get", "list"}) {
		t.Errorf("unexpected perm 0: %+v", perms[0])
	}
	if perms[1].Resource != "services" {
		t.Errorf("unexpected perm 1: %+v", perms[1])
	}

	// Verify apps group resources (prefix applied)
	if perms[2].Resource != "apps/deployments" || !reflect.DeepEqual(perms[2].Actions, []string{"*"}) {
		t.Errorf("unexpected perm 2: %+v", perms[2])
	}
	
	// Verify RoleRef and Source attached correctly
	if perms[0].RoleType != "Role" || perms[0].RoleName != "test-role" || perms[0].Source.BindingName != "test-binding" {
		t.Errorf("role ref / source mapping failed")
	}
}
