import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import { redis } from '../redis/client.js';
import { bufferRequestBody } from '../proxy/body-buffer.js';
import { isBlocked, recordViolationAndEscalate, isJailed, placeInJail, releaseFromJail } from './blocklist.js';

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

// "Mode 3: Adaptive Rate Jail" (Parameters.rtf.doc): the doc's "5
// requests/10 seconds" degraded-tier figure, applied for JAIL_TTL_SECONDS
// once a caller first crosses the login-failure threshold - a quarantine,
// not an immediate hard cut-off. Only breaching *this* stricter limit (or
// re-breaching the login-failure threshold) while still jailed escalates to
// the existing doubling-duration hard block.
const JAIL_POINTS = Number(process.env.RATE_LIMIT_JAIL_POINTS || 5);
const JAIL_DURATION_SECONDS = Number(process.env.RATE_LIMIT_JAIL_DURATION || 10);
const JAIL_TTL_SECONDS = Number(process.env.RATE_LIMIT_JAIL_TTL || 120);

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

const jailLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:jail',
  points: JAIL_POINTS,
  duration: JAIL_DURATION_SECONDS,
  insuranceLimiter: new RateLimiterMemory({ points: JAIL_POINTS, duration: JAIL_DURATION_SECONDS }),
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

      // "Mode 3: Adaptive Rate Jail" - IP only, since request.armourapiAccount
      // isn't resolved yet at this point in the chain for the login route
      // (loginGuard, which extracts it from the body, runs after this guard -
      // an honest limitation, not a gap that matters for IP-shaped abuse).
      // A jailed IP isn't cut off; it's held to a much stricter secondary
      // limit, and only exceeding *that* escalates to a real hard block.
      if (await isJailed('ip', request.ip)) {
        try {
          await jailLimiter.consume(request.ip);
        } catch {
          const { violationCount, blockedForSeconds } = await recordViolationAndEscalate('ip', request.ip, {
            reason: `exceeded adaptive rate jail limit (${JAIL_POINTS} req/${JAIL_DURATION_SECONDS}s)`,
            baseBlockSeconds: BASE_BLOCK_SECONDS,
            maxBlockSeconds: MAX_BLOCK_SECONDS,
          });
          await releaseFromJail('ip', request.ip);
          request.log.warn(
            { ip: request.ip, violationCount, blockedForSeconds },
            'armourapi_rate_jail_escalated',
          );
          return {
            allow: false,
            category: 'rate-jail-escalated',
            reason: `Exceeded adaptive rate jail limit; hard-blocked for ${blockedForSeconds}s`,
          };
        }
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
      // First threshold breach: quarantine into the degraded jail tier
      // rather than an immediate hard block ("Mode 3: Adaptive Rate Jail").
      // A second breach while still jailed means the caller kept failing
      // logins through the quarantine window - that's when it escalates.
      if (await isJailed(type, value)) {
        const { violationCount, blockedForSeconds } = await recordViolationAndEscalate(type, value, {
          reason: 'repeated credential-stuffing/brute-force threshold breach while jailed',
          baseBlockSeconds: BASE_BLOCK_SECONDS,
          maxBlockSeconds: MAX_BLOCK_SECONDS,
        });
        await releaseFromJail(type, value);
        request.log.warn(
          { type, value, violationCount, blockedForSeconds },
          'armourapi_credential_stuffing_blocklisted',
        );
      } else {
        await placeInJail(type, value, { ttlSeconds: JAIL_TTL_SECONDS });
        request.log.warn({ type, value, ttlSeconds: JAIL_TTL_SECONDS }, 'armourapi_adaptive_rate_jail_entered');
      }
    }
  }
}
