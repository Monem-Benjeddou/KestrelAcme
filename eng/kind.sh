#!/usr/bin/env bash
# Creates a local Kubernetes cluster (kind) for the Kubernetes integration tests, with a service account that has
# exactly the permissions the README asks for, and writes its credentials to .kind/. Uses its own kubeconfig file,
# so your current kubectl context is left alone. Then: export KESTRELACME_KUBERNETES="$PWD/.kind/serviceaccount"
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/.kind"
KIND="${KIND:-kind}"
export KUBECONFIG="$DEST/kubeconfig"
mkdir -p "$DEST/serviceaccount"

"$KIND" get clusters | grep -qx kestrelacme || "$KIND" create cluster --name kestrelacme --kubeconfig "$KUBECONFIG" --wait 120s
"$KIND" export kubeconfig --name kestrelacme --kubeconfig "$KUBECONFIG"

kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata: { name: kestrelacme-test }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: app, namespace: kestrelacme-test }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: kestrelacme, namespace: kestrelacme-test }
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, create, update, delete]
  - apiGroups: [coordination.k8s.io]
    resources: [leases]
    verbs: [get, create, update]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: kestrelacme, namespace: kestrelacme-test }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: kestrelacme }
subjects: [{ kind: ServiceAccount, name: app, namespace: kestrelacme-test }]
YAML

kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}' > "$DEST/serviceaccount/server"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 --decode > "$DEST/serviceaccount/ca.crt"
kubectl -n kestrelacme-test create token app --duration 24h > "$DEST/serviceaccount/token"
echo -n kestrelacme-test > "$DEST/serviceaccount/namespace"
echo "export KESTRELACME_KUBERNETES=\"$DEST/serviceaccount\""
