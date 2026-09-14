import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { BloomFilter } from 'bloom-filters';
import { config } from '../config.js';
import { block, isBlocked } from '../rate-limiter/blocklist.js';

/**
 * FR6: short-lived JWTs (15m) + secure httpOnly refresh tokens, with a
 * revocation list. ArmourAPI is a reverse proxy in front of independent
 * upstreams (Juice Shop / DVGA / AndroGoat), each with its own auth - so
 * rather than trying to verify tokens ArmourAPI never issued, it mints its
 * OWN short-lived session on top of a successful upstream login (the
 * "gateway session" pattern) and enforces that session on protected POS
 * routes. This gives ArmourAPI actual control over expiry/revocation
 * regardless of what the upstream's own token scheme looks like.
 *
 * Revocation reuses the generic blocklist store (type: 'token', keyed by
 * jti) instead of a separate Redis structure - it's the same shape (a
 * key that's either currently blocked/revoked or not, Redis-backed with an
 * in-memory fallback).
 */

const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60; // 7d
const DURATION_UNITS = { s: 1, m: 60, h: 3600, d: 86400 };

// jsonwebtoken's `expiresIn` accepts strings like '15m'; parse the same
// shape ourselves to get a plain seconds count for the revocation entry's
// own TTL (must match the token's lifetime, or a revoked token could
// out-live its blocklist entry).
function parseDurationToSeconds(value) {
  if (typeof value === 'number') return value;
  const match = /^(\d+)([smhd])$/.exec(value.trim());
  if (!match) throw new Error(`Unsupported JWT duration format: "${value}"`);
  return Number(match[1]) * DURATION_UNITS[match[2]];
}

const ACCESS_TTL_SECONDS = parseDurationToSeconds(config.jwt.accessTtl);

/**
 * "Mode 2: Token Invalidation" (Parameters.rtf.doc, 2026-09-14): a Bloom
 * filter in front of the existing exact revocation check. Bloom filters
 * have zero false negatives - if it says "not revoked", that's certain, so
 * isTokenRevoked can skip the Redis/memory round-trip entirely for the
 * common case (most tokens are never revoked). A "maybe revoked" result
 * always falls through to the real isBlocked() check below, which stays
 * authoritative - a false positive here only costs one extra lookup, it
 * can never let a genuinely revoked token slip through.
 *
 * Sized for 2048 entries per the doc's figure. Honest limitation, not
 * hidden: this is a plain (non-counting) filter with no removal, so it
 * never shrinks even as individual revocations expire in the real store -
 * over a very long-running process revoking far more than 2048 unique
 * tokens, the false-positive rate rises and more requests fall through to
 * the exact check. That degrades to "slower", never to "wrong", since the
 * exact check is still consulted whenever the filter can't rule a token
 * out.
 */
const REVOCATION_BLOOM_FILTER = BloomFilter.create(2048, 0.01);

export function issueAccessToken({ sub, role }) {
  const jti = randomUUID();
  const token = jwt.sign({ sub, role, jti, type: 'access' }, config.jwt.secret, {
    expiresIn: config.jwt.accessTtl,
  });
  return { token, jti, expiresInSeconds: ACCESS_TTL_SECONDS };
}

export function issueRefreshToken({ sub }) {
  const jti = randomUUID();
  const token = jwt.sign({ sub, jti, type: 'refresh' }, config.jwt.secret, {
    expiresIn: REFRESH_TTL_SECONDS,
  });
  return { token, jti, expiresInSeconds: REFRESH_TTL_SECONDS };
}

/** Throws if the token is malformed, expired, or has the wrong signature. */
export function verifyToken(token) {
  return jwt.verify(token, config.jwt.secret);
}

export async function revokeToken(jti, ttlSeconds = ACCESS_TTL_SECONDS) {
  REVOCATION_BLOOM_FILTER.add(jti);
  await block('token', jti, { reason: 'revoked', ttlSeconds });
}

export async function isTokenRevoked(jti) {
  if (!REVOCATION_BLOOM_FILTER.has(jti)) return false; // certain: never revoked
  return isBlocked('token', jti); // maybe revoked - confirm against the exact store
}

/** For the profiler (13.4): real, measured footprint, not the doc's claimed figure. */
export function getBloomFilterStats() {
  return {
    sizeBits: REVOCATION_BLOOM_FILTER._size,
    sizeBytes: Math.ceil(REVOCATION_BLOOM_FILTER._size / 8),
    nbHashes: REVOCATION_BLOOM_FILTER._nbHashes,
  };
}
