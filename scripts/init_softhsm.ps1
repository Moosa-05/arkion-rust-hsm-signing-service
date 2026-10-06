$TokenLabel = if ($env:HSM_TOKEN_LABEL) { $env:HSM_TOKEN_LABEL } else { "arkion-token" }
$SlotIndex = if ($env:HSM_SLOT_INDEX) { $env:HSM_SLOT_INDEX } else { "0" }
$UserPin = if ($env:HSM_USER_PIN) { $env:HSM_USER_PIN } else { "1234" }
$SoPin = if ($env:HSM_SO_PIN) { $env:HSM_SO_PIN } else { "1234" }
$EcdsaLabel = if ($env:HSM_ECDSA_KEY_LABEL) { $env:HSM_ECDSA_KEY_LABEL } else { "arkion-intermediate-prod" }
$AesLabel = if ($env:HSM_AES_KEY_LABEL) { $env:HSM_AES_KEY_LABEL } else { "arkion-aes-key" }

Write-Host "=== Initializing SoftHSM Token: $TokenLabel ==="
try {
    softhsm2-util --init-token --slot $SlotIndex --label $TokenLabel --so-pin $SoPin --pin $UserPin
} catch {
    Write-Host "Token initialization step completed or skipped."
}

Write-Host "ECDSA Key Label: $EcdsaLabel"
Write-Host "AES Key Label:   $AesLabel"
Write-Host "SoftHSM initialization setup ready."
