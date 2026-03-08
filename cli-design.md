# CLI Tool

object of this CLI tool is to find all permissions associated with with 
kubernetes subjects. Make this plugin available as as kubectl extension.
Write this program in the golang

## Tools cli options

--subjects <list of possible subjects>

### examples:

```shell
kubectl-rbacmap --subjects sa:service-account-name(default namespace)

output format:
Service Account: service-account-name
----
    |
    ---- <resource x> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
    |
    ---- <resource y> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
```
 
```shell
kubectl-rbacmap --subjects sa:service-account-name1, sa:service-account-name2,  -n namespace

output format:
Service Account: service-account-name1
----
    |
    ---- <resource x> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
    |
    ---- <resource y> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole>

Service Account: service-account-name2
----
    |
    ---- <resource x> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
    |
    ---- <resource y> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
```

```shell
kubectl-rbacmap --subjects user:hrishi@example.com

output format:
User: hrishi@example.com
----
    |
    ---- <resource x> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
    |
    ---- <resource y> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
```

```shell
kubectl-rbacmap --subjects User:hrishi@example.com

output format:
User: hrishi@example.com
----
    |
    ---- <resource x> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
    |
    ---- <resource y> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
```

```shell
kubectl-rbacmap --subjects Group:hrishi@example.com

output format:
Group: hrishi@example.com
----
    |
    ---- <resource x> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
    |
    ---- <resource y> : <actions,> : <role/cluster-role,> : <RoleBinding:RoleName:Namespace, ClusterRoleBinding:ClusterRole> 
```

## Implementation Tasks:
- [ ] cmd/ layer/package just cobra CLI interface which invokes the code in the pkg
- [ ] pkg/rbac - accept the list of subjects, query the resources based on the list of subjects, 
- [ ] pkg/kube - this invokes calls to kubernetes resources SA, Roles, ClusterRoles, RoleBinding, ClusterRole binding 
- [ ] pgk/fmt  - format the output as per the example shown in the about code