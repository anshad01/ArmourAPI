import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

/**
 * Threat matrix row "API Abuse / High-Frequency Scraping": simulate a
 * headless-bot burst against the public catalog endpoint and confirm
 * ArmourAPI's global per-IP rate limiter (Phase 5, FR4) throttles it once
 * the burst crosses the configured threshold (default 300 req/60s -
 * RATE_LIMIT_GLOBAL_POINTS). GET /products stays public (no token needed),
 * so this isolates rate-limiting behavior specifically.
 *
 * Run: k6 run -e BASE_URL=http://localhost:8080 test/attack-corpus/k6/scraping-spike.js
 */

const blockedCount = new Counter('armourapi_blocked_responses');
const totalCount = new Counter('armourapi_total_responses');

export const options = {
  scenarios: {
    scraping_burst: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 50,
    },
  },
  thresholds: {
    armourapi_blocked_responses: ['count>0'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function () {
  const res = http.get(`${BASE_URL}/api/v1/products`);
  totalCount.add(1);
  if (res.status === 403) blockedCount.add(1);
  check(res, { 'gateway responded (not a network error)': (r) => r.status !== 0 });
}
