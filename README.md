# kubectl-rbacmap

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

1. Download the latest release from the [Releases page](https://github.com/hrishis/kubectl-rbacmap/releases).
2. Extract the binary and place it in your `$PATH`.

Or compile it from source:

```bash
git clone https://github.com/hrishis/kubectl-rbacmap.git
cd kubectl-rbacmap
make install
```

## Usage

You can invoke the plugin using either `kubectl rbacmap` or as a standalone binary `./kubectl-rbacmap`.

### Basic Queries

Query a ServiceAccount:
```bash
kubectl rbacmap --subjects sa:my-service-account -n kube-system
```

Query a User:
```bash
kubectl rbacmap --subjects user:admin@example.com
```

Query multiple subjects:
```bash
kubectl rbacmap --subjects sa:sa1,user:admin
```

### Cloud Provider Integration (EKS)

The plugin automatically evaluates `aws-auth` in `kube-system` to resolve IAM ARNs.

```bash
kubectl rbacmap --subjects user:arn:aws:iam::123456789012:user/admin
```

This will automatically query the mapped Kubernetes `User` and `Group` associated with that ARN!

### Output Formats

By default, the output is formatted as a kubectl-style aligned table. You can modify this using the `-o` or `--output` flag.

```bash
# Output as markdown table
kubectl rbacmap --subjects group:developers -o markdown

# Output as CSV
kubectl rbacmap --subjects group:developers -o csv
```
