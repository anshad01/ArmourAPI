import http from 'k6/http';
import { check } from 'k6';

/**
 * Medium load tier, per doc Section 6.1: 500 req/s, 50 concurrency, 5-20 KB
 * payload. See light.js for why this targets /app/* rather than a
 * schema-guarded /api/v1/* route.
 *
 * Run: k6 run -e BASE_URL=http://localhost:8080 test/load/k6/medium.js
 */

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const PAYLOAD = JSON.stringify({ padding: 'x'.repeat(12 * 1024) }); // ~12KB, mid-range of 5-20KB

export const options = {
  scenarios: {
    medium_tier: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 50,
      maxVUs: 100,
    },
  },
};

export default function () {
  const res = http.post(`${BASE_URL}/app/bench`, PAYLOAD, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'gateway responded (not a network error)': (r) => r.status !== 0 });
}
