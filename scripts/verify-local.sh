#!/bin/bash
set -euo pipefail

IMAGE="${1:?Usage: verify-local.sh <image-ref>}"

echo "==> Verifying image signature"
cosign verify \
  --certificate-identity-regexp="https://github.com/ex3ndr-bot/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  "$IMAGE"

echo "==> Checking Rekor transparency log"
cosign verify \
  --certificate-identity-regexp="https://github.com/ex3ndr-bot/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --rekor-url=https://rekor.sigstore.dev \
  "$IMAGE"

echo "==> Verification passed"
