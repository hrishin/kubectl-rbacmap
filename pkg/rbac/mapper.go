package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/hrishis/kubectl-rbacmap/pkg/kube"
	"sigs.k8s.io/yaml"
)

// ExpandSubjects takes a list of subjects and resolves external cloud provider
// identities (like AWS IAM ARNs) to their in-cluster Kubernetes identity counterparts
// if possible. It returns a new expanded list containing the original subjects
// and any newly discovered mapped subjects.
func ExpandSubjects(ctx context.Context, client *kube.Client, subjects []Subject) ([]Subject, error) {
	expanded := make([]Subject, 0, len(subjects))
	seen := make(map[string]bool)

	add := func(s Subject) {
		key := fmt.Sprintf("%s:%s:%s", s.Kind, s.Name, s.Namespace)
		if !seen[key] {
			seen[key] = true
			expanded = append(expanded, s)
		}
	}

	awsMapped, err := expandAWSAuth(ctx, client, subjects)
	if err == nil {
		for _, s := range awsMapped {
			add(s)
		}
	}

	for _, s := range subjects {
		add(s)
	}

	// Note on other providers:
	// - GKE: Google Cloud IAM policies are bound to the cluster control plane. There is no standard
	//        in-cluster configmap to read the mappings from. Users map directly to email addresses.
	// - AKS: Uses Entra ID (Azure AD). It maps directly to user emails (UPNs) and Group Object IDs.
	//        No in-cluster mapping exists without querying the MS Graph API.
	// - Alibaba/CoreWeave: Usually relies on a similar webhook authenticator approach where
	//        identity resolution happens externally.

	return expanded, nil
}

// expandAWSAuth retrieves the aws-auth ConfigMap in kube-system and attempts to
// find mappings for any AWS ARN in the provided subjects list.
func expandAWSAuth(ctx context.Context, client *kube.Client, subjects []Subject) ([]Subject, error) {
	cm, err := client.GetConfigMap(ctx, "kube-system", "aws-auth")
	if err != nil {
		return nil, err
	}

	var mapped []Subject

	// Helper to handle aws-auth YAML maps
	processMapList := func(dataStr string, arnKey string) {
		if dataStr == "" {
			return
		}

		var entries []map[string]interface{}
		if err := yaml.Unmarshal([]byte(dataStr), &entries); err != nil {
			return
		}

		for _, entry := range entries {
			entryArn, _ := entry[arnKey].(string)
			username, _ := entry["username"].(string)
			groups, _ := entry["groups"].([]interface{})

			for _, s := range subjects {
				if s.Kind == KindUser {
					// We can match either by the mapped IAM ARN or the resulting username.
					matchedArn := matchAWSARN(s.Name, entryArn)
					matchedUser := (s.Name == username)

					if matchedArn || matchedUser {
						// Track mapped identities for display
						var mappedNames []string
						if matchedArn && username != "" && username != "system:node:{{EC2PrivateDNSName}}" {
							mappedNames = append(mappedNames, "User:"+username)
							mapped = append(mapped, Subject{Kind: KindUser, Name: username})
						}

						for _, g := range groups {
							if gStr, ok := g.(string); ok {
								mappedNames = append(mappedNames, "Group:"+gStr)
								mapped = append(mapped, Subject{Kind: KindGroup, Name: gStr})
							}
						}

						// Attach mapped identities back to the original subject
						// We update it in the subjects slice so the formatter sees it.
						for i := range subjects {
							if subjects[i].Kind == s.Kind && subjects[i].Name == s.Name {
								subjects[i].MappedTo = append(subjects[i].MappedTo, mappedNames...)
							}
						}
					}
				}
			}
		}
	}

	if usersData, ok := cm.Data["mapUsers"]; ok {
		processMapList(usersData, "userarn")
	}

	if rolesData, ok := cm.Data["mapRoles"]; ok {
		processMapList(rolesData, "rolearn")
	}

	return mapped, nil
}

// matchAWSARN checks if a target ARN (from CLI input) matches a mapped ARN
// from the aws-auth ConfigMap. It handles simple string matching as well as
// stripping down STS assumed-role ARNs to their base IAM role ARN.
func matchAWSARN(targetArn, mappedArn string) bool {
	t := strings.ToLower(targetArn)
	m := strings.ToLower(mappedArn)

	if t == m {
		return true
	}

	// Handle STS assumed-role: arn:aws:sts::ACCOUNT:assumed-role/RoleName/SessionName
	// Usually this maps to the rolearn: arn:aws:iam::ACCOUNT:role/RoleName
	if strings.HasPrefix(t, "arn:aws:sts:") && strings.Contains(t, ":assumed-role/") {
		parts := strings.Split(t, ":")
		if len(parts) >= 6 {
			account := parts[4]
			resource := parts[5]
			resParts := strings.Split(resource, "/")
			if len(resParts) >= 2 {
				roleName := resParts[1]
				constructedRole := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName)
				if constructedRole == m {
					return true
				}
			}
		}
	}

	return false
}
