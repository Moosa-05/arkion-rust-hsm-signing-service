#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${TARGET_URL:-http://localhost:8080/v1/sign}"
DURATION="${DURATION:-10s}"

echo "=================================================="
echo "      Arkion HSM Signing Service Load Test        "
echo "=================================================="
echo "Target URL: ${TARGET_URL}"
echo "Duration per concurrency level: ${DURATION}"
echo "--------------------------------------------------"

for VUS in 1 10 100 500; do
  echo ""
  echo ">>> Running Benchmark: Concurrency = ${VUS} callers <<<"
  if command -v k6 &> /dev/null; then
    CONCURRENCY=${VUS} DURATION=${DURATION} TARGET_URL=${TARGET_URL} k6 run scripts/load_test.js
  elif command -v hey &> /dev/null; then
    hey -z "${DURATION}" -c "${VUS}" -m POST \
      -H "Content-Type: application/json" \
      -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"SGVsbG8gQXJraW9u"}' \
      "${TARGET_URL}"
  else
    echo "Neither k6 nor hey installed. Install k6 or hey to execute automated benchmark sweeps."
    exit 1
  fi
done
