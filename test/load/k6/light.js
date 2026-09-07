import http from 'k6/http';
import { check } from 'k6';

/**
 * Light load tier, per doc Section 6.1: 100 req/s, 10 concurrency, 1-5 KB
 * payload. Targets /app/* (Juice Shop passthrough) deliberately, not
 * /api/v1/checkout - that route's schema caps items at 100 entries (~4KB),
 * which would conflate "payload too big for the business schema" with "WAF/
 * proxy overhead under load", the thing NFR1/NFR2 actually care about.
 * /app/* only runs blocklist + rate-limit + WAF (no schema guard), so body
 * size here is purely a WAF/proxy-throughput variable.
 *
 * Run: k6 run -e BASE_URL=http://localhost:8080 test/load/k6/light.js
 */

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const PAYLOAD = JSON.stringify({ padding: 'x'.repeat(3 * 1024) }); // ~3KB, mid-range of 1-5KB

export const options = {
  scenarios: {
    light_tier: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 10,
      maxVUs: 20,
    },
  },
};

export default function () {
  const res = http.post(`${BASE_URL}/app/bench`, PAYLOAD, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'gateway responded (not a network error)': (r) => r.status !== 0 });
}
