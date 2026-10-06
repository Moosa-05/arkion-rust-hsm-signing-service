import http from 'k6/http';
import { check } from 'k6';

const TARGET_URL = __ENV.TARGET_URL || 'http://localhost:8080/v1/sign';
const CONCURRENCY = __ENV.CONCURRENCY ? parseInt(__ENV.CONCURRENCY) : 1;
const DURATION = __ENV.DURATION || '10s';

export const options = {
  vus: CONCURRENCY,
  duration: DURATION,
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const payload = JSON.stringify({
    key_id: 'arkion-intermediate-prod',
    algorithm: 'ECDSA_P256_SHA256',
    payload: 'SGVsbG8gQXJraW9uIEhTTSBMb2FkIFRlc3Q=',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const res = http.post(TARGET_URL, payload, params);

  check(res, {
    'is status 200': (r) => r.status === 200,
    'has valid signature': (r) => r.json() && r.json().signature !== undefined,
  });
}
