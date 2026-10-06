#!/usr/bin/env bash
set -euo pipefail

TOKEN_LABEL="${HSM_TOKEN_LABEL:-arkion-token}"
SLOT_INDEX="${HSM_SLOT_INDEX:-0}"
USER_PIN="${HSM_USER_PIN:-1234}"
SO_PIN="${HSM_SO_PIN:-1234}"

echo "=== Arkion HSM Container Entrypoint Startup ==="

mkdir -p /var/lib/softhsm/tokens

if [ ! -f /etc/softhsm2.conf ]; then
    echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm2.conf
    echo "objectstore.backend = file" >> /etc/softhsm2.conf
    echo "log.level = ERROR" >> /etc/softhsm2.conf
fi

echo "Checking SoftHSM token status..."
if ! softhsm2-util --show-slots | grep -q "${TOKEN_LABEL}"; then
    echo "Initializing SoftHSM token '${TOKEN_LABEL}' on slot ${SLOT_INDEX}..."
    softhsm2-util --init-token --slot "${SLOT_INDEX}" --label "${TOKEN_LABEL}" --so-pin "${SO_PIN}" --pin "${USER_PIN}" || true
else
    echo "SoftHSM token '${TOKEN_LABEL}' already initialized."
fi

if [ -f /app/init_hsm ]; then
    echo "Running key provisioning check..."
    /app/init_hsm || true
fi

echo "Starting Arkion Rust HSM Signing Service..."
exec /app/arkion-rust-hsm-signing-service
