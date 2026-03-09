# kubectl-rbac-map

A `kubectl` plugin that maps Kubernetes RBAC permissions for subjects (ServiceAccounts, Users, Groups) by dynamically evaluating `RoleBindings` and `ClusterRoleBindings`.

It also supports advanced identity mappers like mapping AWS IAM ARNs to underlying EKS RBAC profiles natively!

## Installation

### Via Krew

[Krew](https://krew.sigs.k8s.io/) is the plugin manager for kubectl command-line tool.

```bash
kubectl krew install rbacmap
```

### Manual Install

If you prefer to install it manually:

1. Download the latest release from the [Releases page](https://github.com/hrishin/kubectl-rbacmap/releases).
2. Extract the binary and place it in your `$PATH`.

Or compile it from source:

```bash
git clone https://github.com/hrishin/kubectl-rbacmap.git
cd kubectl-rbacmap
make install
```

## Usage

You can invoke the plugin using either `kubectl rbac-map` or as a standalone binary `./kubectl-rbac-map`.

### Basic Queries

Query a ServiceAccount:
```bash
kubectl rbac-map --subjects sa:aws-load-balancer-controller -n aws-load-balancer-controller

Service Account: aws-load-balancer-controller

RESOURCE                                       ACTIONS                                     ROLE                                                      BINDING
configmaps                                     create,get,patch,update                     role: aws-load-balancer-controller-leader-election-role   RoleBinding: aws-load-balancer-controller-leader-election-role: NS:<aws-load-balancer-controller>
coordination.k8s.io/leases                     create,get,update,patch                     role: aws-load-balancer-controller-leader-election-role   RoleBinding: aws-load-balancer-controller-leader-election-role: NS:<aws-load-balancer-controller>
elbv2.k8s.aws/targetgroupbindings              create,delete,get,list,patch,update,watch   clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
elbv2.k8s.aws/ingressclassparams               get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
events                                         create,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
pods                                           get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/ingressclasses               get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
services                                       get,list,patch,update,watch                 clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
extensions/services                            get,list,patch,update,watch                 clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/services                     get,list,patch,update,watch                 clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
ingresses                                      get,list,patch,update,watch                 clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
extensions/ingresses                           get,list,patch,update,watch                 clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/ingresses                    get,list,patch,update,watch                 clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
nodes                                          get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
namespaces                                     get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
endpoints                                      get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
elbv2.k8s.aws/targetgroupbindings/status       update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
targetgroupbindings/status                     update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
extensions/targetgroupbindings/status          update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/targetgroupbindings/status   update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
elbv2.k8s.aws/pods/status                      update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
pods/status                                    update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
extensions/pods/status                         update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/pods/status                  update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
elbv2.k8s.aws/services/status                  update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
services/status                                update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
extensions/services/status                     update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/services/status              update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
elbv2.k8s.aws/ingresses/status                 update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
ingresses/status                               update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
extensions/ingresses/status                    update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
networking.k8s.io/ingresses/status             update,patch                                clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
discovery.k8s.io/endpointslices                get,list,watch                              clusterrole: aws-load-balancer-controller-role            ClusterRoleBinding: aws-load-balancer-controller-role
```

Query a User:
```bash
 $ kubectl rbac-map --subjects user:hrishi                                                    

Group: system:masters

RESOURCE   ACTIONS   ROLE                         BINDING
*/*        *         clusterrole: cluster-admin   ClusterRoleBinding: cluster-admin
*          *         clusterrole: cluster-admin   ClusterRoleBinding: cluster-admin


User: hrishi
(Mapped to: Group:system:masters)

```

Query multiple subjects:
```bash
kubectl rbac-map --subjects sa:sa1,user:admin
```

### Cloud Provider Integration (EKS)

The plugin automatically evaluates `aws-auth` in `kube-system` to resolve IAM ARNs.

```bash
kubectl rbac-map --subjects user:arn:aws:iam::123456789012:user/admin
```

This will automatically query the mapped Kubernetes `User` and `Group` associated with that ARN!

### Output Formats

By default, the output is formatted as a kubectl-style aligned table. You can modify this using the `-o` or `--output` flag.

```bash
# Output as markdown table
kubectl rbac-map --subjects group:developers -o markdown

# Output as CSV
kubectl rbac-map --subjects group:developers -o csv
```
