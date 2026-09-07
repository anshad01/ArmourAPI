import { issueAccessToken, issueRefreshToken } from './jwt.js';

/**
 * Fastify onSend hook (runs after the upstream has replied but before the
 * response is flushed to the client - unlike onResponse, headers can still
 * be set here). On a successful login response, mints ArmourAPI's own
 * short-lived access token + secure httpOnly refresh-token cookie (FR6),
 * decoupling the client's session from whatever token scheme the upstream
 * itself uses. request.armourapiAccount is set by the login guard (Phase 5)
 * during preHandler, so it's already available here.
 */
export async function attachSessionOnLoginSuccess(request, reply, payload) {
  if (request.armourapiBlockedByGate) return payload;
  if (reply.statusCode < 200 || reply.statusCode >= 300) return payload;

  const sub = request.armourapiAccount || 'unknown';
  const access = issueAccessToken({ sub, role: 'cashier' });
  const refresh = issueRefreshToken({ sub });

  reply.header('X-ArmourAPI-Access-Token', access.token);
  reply.header('X-ArmourAPI-Access-Token-Expires-In', String(access.expiresInSeconds));

  // Fastify special-cases 'set-cookie': reply.header() APPENDS to it rather
  // than replacing (so multiple cookies can be set with repeated calls) -
  // so this only needs the one new cookie, not a read-modify-write of
  // whatever the upstream (possibly already hardened by hardenCookiesOnSend,
  // which runs first) already set.
  const ourCookie = `armourapi_refresh=${refresh.token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${refresh.expiresInSeconds}; Path=/`;
  reply.header('set-cookie', ourCookie);

  return payload;
}

const SECURE_COOKIE_FLAGS = ['httponly', 'secure', 'samesite'];

function hardenOneCookie(cookie) {
  const parts = cookie.split(';').map((p) => p.trim());
  const lowerParts = parts.map((p) => p.toLowerCase());
  const missing = SECURE_COOKIE_FLAGS.filter((flag) => !lowerParts.some((p) => p.startsWith(flag)));

  for (const flag of missing) {
    if (flag === 'samesite') parts.push('SameSite=Lax');
    else parts.push(flag === 'httponly' ? 'HttpOnly' : 'Secure');
  }
  return parts.join('; ');
}

/**
 * FR6 "secure cookie flags": upstream apps (Juice Shop et al.) don't
 * necessarily set Secure/HttpOnly/SameSite on their own cookies - ArmourAPI
 * hardens any Set-Cookie header passing through it, regardless of route,
 * rather than trusting the upstream to have gotten this right.
 */
export async function hardenCookiesOnSend(_request, reply, payload) {
  const existing = reply.getHeader('set-cookie');
  if (!existing) return payload;

  const cookies = Array.isArray(existing) ? existing : [existing];
  // reply.header('set-cookie', ...) appends rather than replaces (see
  // attachSessionOnLoginSuccess above) - remove the un-hardened values first
  // so this is a genuine in-place transform, not an addition alongside them.
  reply.removeHeader('set-cookie');
  reply.header('set-cookie', cookies.map(hardenOneCookie));
  return payload;
}
