#!/bin/bash
set -euo pipefail

IMAGE="${1:?Usage: publish.sh <image-ref>}"
MEASUREMENTS_FILE="${2:?Usage: publish.sh <image-ref> <measurements.json>}"

echo "==> Signing image with Cosign (keyless)"
cosign sign --yes "$IMAGE"

echo "==> Publishing measurements to Rekor"
rekor-cli upload \
  --artifact "$MEASUREMENTS_FILE" \
  --type hashedrekord \
  --rekor_server https://rekor.sigstore.dev

echo "==> Published to transparency log"
