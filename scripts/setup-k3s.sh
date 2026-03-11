#!/bin/bash
set -euo pipefail

echo "==> Installing k3s (CIS hardened)"
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--protect-kernel-defaults --secrets-encryption" sh -

echo "==> Installing Kyverno"
kubectl apply -f https://github.com/kyverno/kyverno/releases/latest/download/install.yaml

echo "==> Installing Kata Containers"
kubectl apply -f https://raw.githubusercontent.com/kata-containers/kata-containers/main/tools/packaging/kata-deploy/kata-deploy/base/kata-deploy.yaml

echo "==> Setup complete"
echo "Next: ./scripts/setup-kbs.sh"
