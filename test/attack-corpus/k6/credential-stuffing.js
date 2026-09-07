import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

/**
 * Section 3.3's "Credential Stuffing Spike" traffic scenario: simulate a
 * sudden surge of login attempts against ArmourAPI's /api/v1/auth/login and
 * confirm the rate limiter (Phase 5, FR4) blocklists the offending source
 * once the failure threshold is crossed, rather than letting the ramp
 * through unthrottled.
 *
 * Run: k6 run -e BASE_URL=http://localhost:8080 test/attack-corpus/k6/credential-stuffing.js
 * (k6 is a standalone binary, not an npm package - install separately, see
 * test/attack-corpus/README.md)
 */

const blockedCount = new Counter('armourapi_blocked_responses');
const totalCount = new Counter('armourapi_total_responses');

export const options = {
  scenarios: {
    credential_stuffing: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 20 },
        { duration: '20s', target: 20 },
        { duration: '5s', target: 0 },
      ],
    },
  },
  thresholds: {
    // Fails the run if NOTHING gets blocked - the whole point of this
    // scenario is proving the rate limiter actually engages under load.
    armourapi_blocked_responses: ['count>0'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function () {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: 'victim@k6-corpus.com', password: `guess-${__VU}-${__ITER}` }),
    { headers: { 'Content-Type': 'application/json' } },
  );

  totalCount.add(1);
  if (res.status === 403) blockedCount.add(1);

  check(res, { 'gateway responded (not a network error)': (r) => r.status !== 0 });

  sleep(0.2);
}
