import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
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
  await block('token', jti, { reason: 'revoked', ttlSeconds });
}

export async function isTokenRevoked(jti) {
  return isBlocked('token', jti);
}
