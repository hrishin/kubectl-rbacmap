package rbac

import (
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestParseResourceInput(t *testing.T) {
	tests := []struct {
		input     string
		wantGroup string
		wantRes   string
	}{
		{"pods", "", "pods"},
		{"secrets", "", "secrets"},
		{"deployments.apps", "apps", "deployments"},
		{"ingresses.networking.k8s.io", "networking.k8s.io", "ingresses"},
		{"apps/deployments", "apps", "deployments"},
		{"networking.k8s.io/ingresses", "networking.k8s.io", "ingresses"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			group, res := parseResourceInput(tt.input)
			if group != tt.wantGroup || res != tt.wantRes {
				t.Errorf("parseResourceInput(%q) = (%q, %q); want (%q, %q)",
					tt.input, group, res, tt.wantGroup, tt.wantRes)
			}
		})
	}
}

func TestRuleMatchesResource(t *testing.T) {
	tests := []struct {
		name        string
		rule        rbacv1.PolicyRule
		targetGroup string
		targetRes   string
		wantMatch   bool
	}{
		{
			name: "exact core resource match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
			targetGroup: "",
			targetRes:   "pods",
			wantMatch:   true,
		},
		{
			name: "wildcard resource matches any resource",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"*"},
				Verbs:     []string{"get"},
			},
			targetGroup: "",
			targetRes:   "pods",
			wantMatch:   true,
		},
		{
			name: "wildcard group matches any group",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"*"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get"},
			},
			targetGroup: "apps",
			targetRes:   "deployments",
			wantMatch:   true,
		},
		{
			name: "wrong resource no match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get"},
			},
			targetGroup: "",
			targetRes:   "pods",
			wantMatch:   false,
		},
		{
			name: "resource matches but wrong group",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"extensions"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get"},
			},
			targetGroup: "apps",
			targetRes:   "deployments",
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleMatchesResource(tt.rule, tt.targetGroup, tt.targetRes)
			if got != tt.wantMatch {
				t.Errorf("ruleMatchesResource() = %v; want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatchedVerbs(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"*"},
		},
	}

	tests := []struct {
		name        string
		targetGroup string
		targetRes   string
		filterVerbs []string
		wantVerbs   []string
	}{
		{
			name:        "no filter returns all verbs",
			targetGroup: "",
			targetRes:   "pods",
			filterVerbs: nil,
			wantVerbs:   []string{"get", "list", "watch"},
		},
		{
			name:        "filter limits to intersection",
			targetGroup: "",
			targetRes:   "pods",
			filterVerbs: []string{"get", "delete"},
			wantVerbs:   []string{"get"},
		},
		{
			name:        "wildcard rule with filter returns filter verbs",
			targetGroup: "apps",
			targetRes:   "deployments",
			filterVerbs: []string{"get", "delete"},
			wantVerbs:   []string{"get", "delete"},
		},
		{
			name:        "wildcard rule with no filter returns wildcard",
			targetGroup: "apps",
			targetRes:   "deployments",
			filterVerbs: nil,
			wantVerbs:   []string{"*"},
		},
		{
			name:        "no matching resource returns nil",
			targetGroup: "",
			targetRes:   "secrets",
			filterVerbs: nil,
			wantVerbs:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchedVerbs(rules, tt.targetGroup, tt.targetRes, tt.filterVerbs)
			if !reflect.DeepEqual(got, tt.wantVerbs) {
				t.Errorf("matchedVerbs() = %v; want %v", got, tt.wantVerbs)
			}
		})
	}
}

func TestSubjectFromRBACSubject(t *testing.T) {
	tests := []struct {
		name             string
		input            rbacv1.Subject
		defaultNamespace string
		want             Subject
	}{
		{
			name:  "service account with namespace",
			input: rbacv1.Subject{Kind: "ServiceAccount", Name: "my-sa", Namespace: "prod"},
			want:  Subject{Kind: KindServiceAccount, Name: "my-sa", Namespace: "prod"},
		},
		{
			name:             "service account without namespace uses default",
			input:            rbacv1.Subject{Kind: "ServiceAccount", Name: "my-sa"},
			defaultNamespace: "fallback",
			want:             Subject{Kind: KindServiceAccount, Name: "my-sa", Namespace: "fallback"},
		},
		{
			name:  "user",
			input: rbacv1.Subject{Kind: "User", Name: "alice"},
			want:  Subject{Kind: KindUser, Name: "alice"},
		},
		{
			name:  "group",
			input: rbacv1.Subject{Kind: "Group", Name: "system:masters"},
			want:  Subject{Kind: KindGroup, Name: "system:masters"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subjectFromRBACSubject(tt.input, tt.defaultNamespace)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("subjectFromRBACSubject() = %+v; want %+v", got, tt.want)
			}
		})
	}
}
