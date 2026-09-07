import Redis from 'ioredis';
import { config } from '../config.js';
import { logger } from '../logging/logger.js';

// Rate limiting / blocklist state needs to survive across ArmourAPI instances
// and restarts (Redis), but the gateway must keep working if Redis is briefly
// unreachable - rate-limiter-flexible's RateLimiterRedis + insuranceLimiter
// pattern handles per-call fallback; this client just needs to never crash
// the process or block startup while Redis is down.
export const redis = new Redis(config.redisUrl, {
  lazyConnect: true,
  maxRetriesPerRequest: 1,
  // Fail fast instead of queueing commands while disconnected - the
  // in-memory fallbacks depend on Redis calls rejecting quickly, not hanging
  // until reconnection, to keep the FR1 latency budget intact.
  enableOfflineQueue: false,
  retryStrategy: (attempt) => Math.min(attempt * 200, 2000),
});

let warnedOnce = false;
redis.on('error', (err) => {
  if (!warnedOnce) {
    logger.warn({ err: err.message }, 'redis unavailable - rate limiter/blocklist falling back to in-memory');
    warnedOnce = true;
  }
});

redis.connect().catch(() => {
  // Swallow - the 'error' handler above already logged it, and every
  // consumer (RateLimiterRedis's insuranceLimiter, the blocklist store) has
  // its own in-memory fallback.
});
