#!/usr/bin/env bash
set -euo pipefail

TOKEN_LABEL="${HSM_TOKEN_LABEL:-arkion-token}"
SLOT_INDEX="${HSM_SLOT_INDEX:-0}"
USER_PIN="${HSM_USER_PIN:-1234}"
SO_PIN="${HSM_SO_PIN:-1234}"
ECDSA_LABEL="${HSM_ECDSA_KEY_LABEL:-arkion-intermediate-prod}"
AES_LABEL="${HSM_AES_KEY_LABEL:-arkion-aes-key}"

echo "=== Initializing SoftHSM Token: ${TOKEN_LABEL} ==="
softhsm2-util --init-token --slot "${SLOT_INDEX}" --label "${TOKEN_LABEL}" --so-pin "${SO_PIN}" --pin "${USER_PIN}" || true

echo "=== Key generation will be performed on service startup or via PKCS#11 ==="
echo "ECDSA Key Label: ${ECDSA_LABEL}"
echo "AES Key Label:   ${AES_LABEL}"
echo "SoftHSM initialization completed successfully."
