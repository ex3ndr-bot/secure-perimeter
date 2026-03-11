#!/bin/bash
set -euo pipefail

echo "==> Deploying Trustee KBS"
kubectl create namespace trustee || true

# Apply KBS manifests
kubectl apply -f attestation/kbs/

echo "==> KBS deployed"
echo "Update reference values in attestation/kbs/reference-values.yaml after building"
