document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  const btnHealth = document.getElementById('btnHealth');
  if (btnHealth) {
    btnHealth.addEventListener('click', checkHealth);
  }
});

async function checkHealth() {
  const indicator = document.getElementById('statusIndicator');
  const label = document.getElementById('statusLabel');

  try {
    const response = await fetch('/health');
    if (response.ok) {
      const data = await response.json();
      if (data.status === 'ok') {
        indicator.className = 'status-indicator online';
        label.textContent = 'Service Online';
        return;
      }
    }
    throw new Error('Health check failed');
  } catch (err) {
    indicator.className = 'status-indicator offline';
    label.textContent = 'Service Offline';
  }
}

async function handleSign() {
  const keyId = document.getElementById('keyId').value.trim();
  const algorithm = document.getElementById('algorithm').value;
  const payloadText = document.getElementById('payload').value;
  
  const btnSign = document.getElementById('btnSign');
  const btnSignText = document.getElementById('btnSignText');
  const spinner = document.getElementById('signSpinner');
  
  const resultBadge = document.getElementById('resultBadge');
  const feedbackBanner = document.getElementById('feedbackBanner');
  const resultOutput = document.getElementById('resultOutput');

  if (!keyId) {
    showBanner('error', 'Key Identity cannot be empty');
    return;
  }

  // UTF-8 Base64 Encoding
  let payloadB64;
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(payloadText);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    payloadB64 = btoa(binary);
  } catch (e) {
    showBanner('error', 'Failed to Base64 encode payload text');
    return;
  }

  // Set loading state
  btnSign.disabled = true;
  btnSignText.textContent = 'Signing...';
  spinner.classList.remove('hidden');

  try {
    const res = await fetch('/v1/sign', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        key_id: keyId,
        algorithm: algorithm,
        payload: payloadB64,
      }),
    });

    const data = await res.json();

    if (res.ok) {
      resultBadge.className = 'badge badge-success';
      resultBadge.textContent = '200 OK';

      showBanner('success', 'Signature generated successfully using HSM-backed key.');

      resultOutput.innerHTML = `
        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">HTTP Status</div>
            <div class="meta-value" style="color: var(--success);">200 OK</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Execution Duration</div>
            <div class="meta-value">${data.duration_ms} ms</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Key Identity</div>
            <div class="meta-value">${escapeHtml(data.key_id)}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Algorithm</div>
            <div class="meta-value">${escapeHtml(data.algorithm)}</div>
          </div>
        </div>

        <div class="meta-item" style="margin-bottom: 0.85rem;">
          <div class="meta-label">Base64 Encoded Payload</div>
          <div class="code-block">${escapeHtml(payloadB64)}</div>
        </div>

        <div class="meta-item">
          <div class="meta-label">Base64 ECDSA Signature</div>
          <div class="code-block" id="sigOutput">${escapeHtml(data.signature)}</div>
          <div class="action-row">
            <button class="btn btn-secondary btn-sm" id="btnCopy" onclick="copySignature()">Copy Signature</button>
          </div>
        </div>
      `;
    } else {
      resultBadge.className = 'badge badge-error';
      resultBadge.textContent = `${res.status} Error`;

      showBanner('error', `Error: ${escapeHtml(data.message || 'Signing failed')}`);

      resultOutput.innerHTML = `
        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">HTTP Status</div>
            <div class="meta-value" style="color: var(--error);">${res.status}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Error Code</div>
            <div class="meta-value" style="color: var(--error);">${escapeHtml(data.error || 'UNKNOWN_ERROR')}</div>
          </div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Error Message</div>
          <div class="meta-value">${escapeHtml(data.message || 'An error occurred during HSM processing')}</div>
        </div>
      `;
    }
  } catch (err) {
    resultBadge.className = 'badge badge-error';
    resultBadge.textContent = 'Network Error';
    showBanner('error', `Network error: ${escapeHtml(err.message)}`);
    resultOutput.innerHTML = `
      <div class="meta-item">
        <div class="meta-label">Error</div>
        <div class="meta-value" style="color: var(--error);">${escapeHtml(err.message)}</div>
      </div>
    `;
  } finally {
    btnSign.disabled = false;
    btnSignText.textContent = 'Sign with HSM';
    spinner.classList.add('hidden');
  }
}

function handleClear() {
  document.getElementById('keyId').value = 'arkion-intermediate-prod';
  document.getElementById('algorithm').value = 'ECDSA_P256_SHA256';
  document.getElementById('payload').value = 'Hello Arkion';

  const resultBadge = document.getElementById('resultBadge');
  const feedbackBanner = document.getElementById('feedbackBanner');
  const resultOutput = document.getElementById('resultOutput');

  resultBadge.className = 'badge badge-idle';
  resultBadge.textContent = 'Awaiting Request';
  feedbackBanner.className = 'banner hidden';
  feedbackBanner.innerHTML = '';
  resultOutput.innerHTML = `
    <div class="placeholder-icon">🛡️</div>
    <p>Submit a request to execute non-exportable HSM signing.</p>
  `;
}

function copySignature() {
  const sigElement = document.getElementById('sigOutput');
  const btnCopy = document.getElementById('btnCopy');
  if (!sigElement || !btnCopy) return;

  const sigText = sigElement.textContent;
  navigator.clipboard.writeText(sigText).then(() => {
    const originalText = btnCopy.textContent;
    btnCopy.textContent = 'Copied!';
    setTimeout(() => {
      btnCopy.textContent = originalText;
    }, 2000);
  }).catch(() => {
    alert('Failed to copy signature to clipboard');
  });
}

function showBanner(type, message) {
  const feedbackBanner = document.getElementById('feedbackBanner');
  feedbackBanner.className = `banner banner-${type}`;
  feedbackBanner.textContent = message;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
}
