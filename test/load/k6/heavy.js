import http from 'k6/http';
import { check } from 'k6';

/**
 * Heavy load tier, per doc Section 6.1: 1000 req/s, 100 concurrency, 20-50 KB
 * payload. See light.js for why this targets /app/* rather than a
 * schema-guarded /api/v1/* route.
 *
 * Run: k6 run -e BASE_URL=http://localhost:8080 test/load/k6/heavy.js
 */

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const PAYLOAD = JSON.stringify({ padding: 'x'.repeat(35 * 1024) }); // ~35KB, mid-range of 20-50KB

export const options = {
  scenarios: {
    heavy_tier: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 100,
      maxVUs: 200,
    },
  },
};

export default function () {
  const res = http.post(`${BASE_URL}/app/bench`, PAYLOAD, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'gateway responded (not a network error)': (r) => r.status !== 0 });
}
