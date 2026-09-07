import { redis } from '../redis/client.js';

/**
 * Temporary blocklist for IPs/accounts, backed by Redis (TTL'd keys) with an
 * in-memory mirror as a fallback when Redis is unreachable - same rationale
 * as the rate limiters (see redis/client.js). Powers both the automatic
 * escalation in rate-limiter/index.js and the manual
 * POST /api/v1/security/blocklist admin endpoint.
 */
const PREFIX = 'armourapi:blocklist:';
const memoryStore = new Map(); // key -> { expiresAt: number, reason: string }

function memoryKey(type, value) {
  return `${type}:${value}`;
}

function isExpired(entry) {
  return !entry || entry.expiresAt <= Date.now();
}

export async function block(type, value, { reason = 'manual', ttlSeconds = 900 } = {}) {
  const key = memoryKey(type, value);
  memoryStore.set(key, { expiresAt: Date.now() + ttlSeconds * 1000, reason });

  try {
    await redis.set(PREFIX + key, JSON.stringify({ reason, blockedAt: Date.now() }), 'EX', ttlSeconds);
  } catch {
    // Redis unavailable - the in-memory entry above still enforces the block
    // on this instance, which is enough for a single-instance dev/demo setup.
  }
}

export async function isBlocked(type, value) {
  const key = memoryKey(type, value);

  try {
    const hit = await redis.exists(PREFIX + key);
    if (hit) return true;
  } catch {
    // fall through to memory check below
  }

  const entry = memoryStore.get(key);
  if (isExpired(entry)) {
    memoryStore.delete(key);
    return false;
  }
  return true;
}

const memoryViolations = new Map(); // key -> { count: number, expiresAt: number }
const VIOLATION_WINDOW_SECONDS = 3600;

/**
 * Progressive delays/tarpitting (doc Section 4.3): each repeat threshold
 * breach within the violation window doubles the block duration, capped at
 * maxBlockSeconds, instead of always applying the same short block.
 */
export async function recordViolationAndEscalate(
  type,
  value,
  { reason, baseBlockSeconds = 30, maxBlockSeconds = 900 } = {},
) {
  const key = memoryKey(type, value);
  let count;

  try {
    count = await redis.incr(`armourapi:violations:${key}`);
    if (count === 1) await redis.expire(`armourapi:violations:${key}`, VIOLATION_WINDOW_SECONDS);
  } catch {
    const entry = memoryViolations.get(key);
    count = !isExpired(entry) ? entry.count + 1 : 1;
    memoryViolations.set(key, { count, expiresAt: Date.now() + VIOLATION_WINDOW_SECONDS * 1000 });
  }

  const ttlSeconds = Math.min(maxBlockSeconds, baseBlockSeconds * 2 ** (count - 1));
  await block(type, value, { reason, ttlSeconds });
  return { violationCount: count, blockedForSeconds: ttlSeconds };
}

/** Best-effort listing for the admin API - reflects only entries this instance knows about. */
export function listMemoryBlocklist() {
  const now = Date.now();
  return [...memoryStore.entries()]
    .filter(([, entry]) => entry.expiresAt > now)
    .map(([key, entry]) => {
      const [type, ...rest] = key.split(':');
      return { type, value: rest.join(':'), reason: entry.reason, expiresAt: entry.expiresAt };
    });
}
