import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import { redis } from '../redis/client.js';
import { bufferRequestBody } from '../proxy/body-buffer.js';
import { isBlocked, recordViolationAndEscalate } from './blocklist.js';

/**
 * FR4: rate-limit and flag credential-stuffing/brute-force patterns on auth
 * endpoints. Two tiers per the doc's "Multi-tier Token Bucket Rate Limiting":
 *  - a broad per-IP request-rate limiter across all proxied traffic
 *  - a narrow per-IP AND per-account failed-login counter on /auth/login,
 *    since credential stuffing often spreads across many IPs against one
 *    account (or one PIN against many accounts) - IP-only limiting misses
 *    that shape, per the threat matrix's "thousands of 4-digit PINs".
 * Both use RateLimiterRedis with a RateLimiterMemory insuranceLimiter, so
 * the gateway keeps working (single-instance only) if Redis is down.
 */

const GLOBAL_POINTS = Number(process.env.RATE_LIMIT_GLOBAL_POINTS || 300);
const GLOBAL_DURATION_SECONDS = Number(process.env.RATE_LIMIT_GLOBAL_DURATION || 60);
const LOGIN_FAIL_POINTS = Number(process.env.RATE_LIMIT_LOGIN_FAIL_POINTS || 5);
const LOGIN_FAIL_DURATION_SECONDS = Number(process.env.RATE_LIMIT_LOGIN_FAIL_DURATION || 60);
const BASE_BLOCK_SECONDS = 30;
const MAX_BLOCK_SECONDS = 900; // 15 min

const globalLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:global',
  points: GLOBAL_POINTS,
  duration: GLOBAL_DURATION_SECONDS,
  insuranceLimiter: new RateLimiterMemory({ points: GLOBAL_POINTS, duration: GLOBAL_DURATION_SECONDS }),
});

const loginFailureLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:login_fail',
  points: LOGIN_FAIL_POINTS,
  duration: LOGIN_FAIL_DURATION_SECONDS,
  insuranceLimiter: new RateLimiterMemory({
    points: LOGIN_FAIL_POINTS,
    duration: LOGIN_FAIL_DURATION_SECONDS,
  }),
});

// Common field names across the sort of login payloads Juice Shop/AndroGoat
// use. Best-effort - if none match, account-level tracking is skipped and
// IP-level tracking still applies.
const ACCOUNT_FIELDS = ['email', 'username', 'user', 'userId', 'pin'];

function extractAccountIdentifier(bodyBuffer) {
  if (!bodyBuffer || bodyBuffer.length === 0) return undefined;
  try {
    const parsed = JSON.parse(bodyBuffer.toString('utf8'));
    for (const field of ACCOUNT_FIELDS) {
      if (typeof parsed?.[field] === 'string' && parsed[field]) return parsed[field];
    }
  } catch {
    // not JSON - nothing to extract
  }
  return undefined;
}

/**
 * Blocklist guard - runs first, before the WAF/GraphQL scans, so an already-
 * blocked IP or account gets rejected without spending a WAF transaction.
 */
export function createBlocklistGuard() {
  return {
    name: 'blocklist',
    async scan(request) {
      if (await isBlocked('ip', request.ip)) {
        return { allow: false, category: 'blocklisted', reason: 'IP is temporarily blocklisted' };
      }
      const account = request.armourapiAccount;
      if (account && (await isBlocked('account', account))) {
        return { allow: false, category: 'blocklisted', reason: 'Account is temporarily blocklisted' };
      }
      return { allow: true };
    },
  };
}

/** General per-IP request-rate limiter across all proxied traffic. */
export function createGlobalRateLimitGuard() {
  return {
    name: 'rate-limiter',
    async scan(request) {
      try {
        await globalLimiter.consume(request.ip);
        return { allow: true };
      } catch {
        return {
          allow: false,
          category: 'rate-limit',
          reason: `More than ${GLOBAL_POINTS} requests per ${GLOBAL_DURATION_SECONDS}s from this IP`,
        };
      }
    },
  };
}

/**
 * Login-route-specific preHandler: peeks at the body to extract an account
 * identifier (stashed on request.armourapiAccount for the blocklist guard
 * and the onResponse tracker below) and pre-checks the account-level
 * failure limiter. Does not consume points itself - only recordLoginOutcome
 * (called from onResponse, after we know whether auth actually failed) does.
 */
export function createLoginGuard() {
  return {
    name: 'login-guard',
    async scan(request) {
      const bodyBuffer = await bufferRequestBody(request);
      request.armourapiAccount = extractAccountIdentifier(bodyBuffer);
      return { allow: true };
    },
  };
}

/**
 * Registered as a Fastify onResponse hook on the login route. Only the
 * upstream's response tells us whether the login actually failed, so the
 * failure-counting has to happen after the proxy returns, not in a
 * preHandler. On threshold breach, escalates to a temporary blocklist entry
 * with a doubling block duration per repeat offense (tarpitting).
 */
export async function recordLoginOutcome(request, reply) {
  // A request ArmourAPI itself rejected (blocklist/rate-limit/WAF) never
  // reached the upstream, so its status code says nothing about whether the
  // *credentials* were valid - only a response that actually came back from
  // the upstream counts as a login failure.
  if (request.armourapiBlockedByGate) return;

  const isFailure = reply.statusCode === 401 || reply.statusCode === 403;
  if (!isFailure) return;

  const targets = [['ip', request.ip]];
  if (request.armourapiAccount) targets.push(['account', request.armourapiAccount]);

  for (const [type, value] of targets) {
    try {
      await loginFailureLimiter.consume(value);
    } catch {
      const { violationCount, blockedForSeconds } = await recordViolationAndEscalate(type, value, {
        reason: 'credential-stuffing/brute-force threshold exceeded',
        baseBlockSeconds: BASE_BLOCK_SECONDS,
        maxBlockSeconds: MAX_BLOCK_SECONDS,
      });
      request.log.warn(
        { type, value, violationCount, blockedForSeconds },
        'armourapi_credential_stuffing_blocklisted',
      );
    }
  }
}
